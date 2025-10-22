#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/openvpn_admin_panel}"
REPO="lekha100101/openvpn-admin"
RELEASE="${RELEASE:-}"               # пример: export RELEASE=v1.1.0 ; пусто = main
PY_BIN="${PY_BIN:-python3}"

echo "[0/9] Проверка инструментов и установка зависимостей..."
if command -v dnf >/dev/null 2>&1; then
  sudo dnf -y install python3 python3-pip sqlite unzip rsync curl git tar || true
elif command -v yum >/dev/null 2>&1; then
  sudo yum -y install python3 python3-pip sqlite unzip rsync curl git tar || true
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y python3 python3-venv python3-pip sqlite3 unzip rsync curl git tar || true
else
  echo "❌ Неизвестный пакетный менеджер. Установи вручную python3, pip, git, rsync, unzip, sqlite, curl, tar."
  exit 1
fi

for bin in curl rsync unzip tar; do
  command -v "$bin" >/dev/null || { echo "❌ Не найден $bin"; exit 1; }
done

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

if [ -n "$RELEASE" ]; then
  ZIP_URL="https://github.com/${REPO}/archive/refs/tags/${RELEASE}.zip"
  echo "[1/9] Скачиваю релиз ${RELEASE} (${ZIP_URL})..."
else
  ZIP_URL="https://github.com/${REPO}/archive/refs/heads/main.zip"
  echo "[1/9] Скачиваю ветку main (${ZIP_URL})..."
fi

curl -fL "$ZIP_URL" -o "$TMP_DIR/src.zip"
unzip -q "$TMP_DIR/src.zip" -d "$TMP_DIR"
SRC_DIR="$(find "$TMP_DIR" -maxdepth 1 -type d -name 'openvpn-admin-*' -print -quit)"
[ -d "$SRC_DIR" ] || { echo "❌ Не удалось распаковать исходники"; exit 1; }

echo "[2/9] Бэкап текущей установки..."
sudo mkdir -p "$APP_DIR"; sudo chown -R "$USER:$USER" "$APP_DIR"
mkdir -p "$APP_DIR"/{instance,logs}
BK_DIR="/root/ovpn_admin_backups"; sudo mkdir -p "$BK_DIR"
STAMP="$(date +%F_%H%M%S)"
if command -v tar >/dev/null 2>&1; then
  sudo tar -czf "$BK_DIR/backup_${STAMP}.tgz" --exclude .venv --exclude .git -C "$APP_DIR" . || true
  echo "   ✅ Бэкап: $BK_DIR/backup_${STAMP}.tgz"
else
  echo "   ⚠️ tar не найден — делаю копию каталогов"
  sudo mkdir -p "$BK_DIR/$STAMP"
  sudo rsync -a --exclude '.venv' --exclude '.git' "$APP_DIR/" "$BK_DIR/$STAMP/"
  echo "   ✅ Копия: $BK_DIR/$STAMP/"
fi

echo "[3/9] Обновляю файлы (instance/ и logs/ не трогаем)..."
RSYNC_LIST=(
  "app.py"
  "config.py"
  "extensions.py"
  "models.py"
  "setup_admin.py"
  "create_admin.py"
  "requirements.txt"
  "auth-check.sh"
  "templates"
  "static"
  "scripts"
  "docs"
)
for item in "${RSYNC_LIST[@]}"; do
  if [ -e "$SRC_DIR/$item" ]; then
    rsync -a --delete --exclude 'instance' --exclude 'logs' "$SRC_DIR/$item" "$APP_DIR/" || true
  fi
done

# Особое правило: client-template.ovpn НЕ перезаписывать
if [ -e "$APP_DIR/client-template.ovpn" ]; then
  echo "   ⚙️ client-template.ovpn уже существует — не заменяю."
else
  if [ -e "$SRC_DIR/client-template.ovpn" ]; then
    cp "$SRC_DIR/client-template.ovpn" "$APP_DIR/"
    echo "   ✅ client-template.ovpn добавлен."
  fi
fi

echo "[4/9] Обновляю виртуальное окружение и зависимости..."
cd "$APP_DIR"
if ! "$PY_BIN" -m venv .venv 2>/dev/null; then
  echo "   ⏳ venv модуль недоступен, устанавливаю virtualenv..."
  sudo "${PY_BIN}" -m pip install --upgrade pip || true
  sudo "${PY_BIN}" -m pip install virtualenv
  "${PY_BIN}" -m virtualenv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate
python -m pip install --upgrade pip
[ -f requirements.txt ] && python -m pip install -r requirements.txt

mkdir -p instance logs

echo "[5/9] Применяю миграции БД..."
python - <<'PY'
from app import create_app
from extensions import db
app = create_app()
with app.app_context():
    db.create_all()
print("[OK] db.create_all() выполнен")
PY

sqlite3 "$APP_DIR/instance/data.db" "
PRAGMA foreign_keys=off;
BEGIN;
CREATE TABLE IF NOT EXISTS audit_log_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER,
  username TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  status TEXT NOT NULL,
  details TEXT,
  ip_address TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(admin_id) REFERENCES admin(id) ON DELETE SET NULL
);
INSERT INTO audit_log_new (admin_id, username, action, target_type, target_id, status, details, ip_address, user_agent, created_at)
SELECT admin_id, username, action, target_type, target_id, status, details, ip_address, user_agent,
       COALESCE(created_at, datetime('now'))
FROM audit_log
ON CONFLICT DO NOTHING;
DROP TABLE IF EXISTS audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_admin ON audit_log(admin_id);
COMMIT;
PRAGMA foreign_keys=on;
" 2>/dev/null || true

sqlite3 "$APP_DIR/instance/data.db" "
ALTER TABLE admin ADD COLUMN role TEXT DEFAULT 'admin';
ALTER TABLE admin ADD COLUMN is_active INTEGER DEFAULT 1;
ALTER TABLE admin ADD COLUMN last_login_at TEXT;
" 2>/dev/null || true

# === ВСЕГДА спросить логин/пароль супер-админа и создать/обновить ===
echo "[6/9] Создание/обновление супер-админа..."
SUPERADMIN_USER=""
while [ -z "${SUPERADMIN_USER}" ]; do
  read -r -p "Логин супер-админа: " SUPERADMIN_USER
done

while true; do
  read -rs -p "Пароль супер-админа: " P1; echo
  read -rs -p "Повторите пароль: " P2; echo
  if [ -z "$P1" ]; then
    echo "Пароль не может быть пустым."
    continue
  fi
  if [ "$P1" != "$P2" ]; then
    echo "Пароли не совпадают. Повторите попытку."
    continue
  fi
  SUPERADMIN_PASS="$P1"
  unset P1 P2
  break
done

SUPERADMIN_USER="$SUPERADMIN_USER" SUPERADMIN_PASS="$SUPERADMIN_PASS" python - <<'PY'
import os
from app import create_app
from extensions import db
from models import Admin

user = os.environ["SUPERADMIN_USER"]
pw   = os.environ["SUPERADMIN_PASS"]

app = create_app()
with app.app_context():
    db.create_all()
    a = Admin.query.filter_by(username=user).first()
    if a:
        a.set_password(pw)
        a.role = "superadmin"
        a.is_active = True
        db.session.commit()
        print(f"[OK] Обновлён админ: {a.username} (role=superadmin, активирован)")
    else:
        a = Admin(username=user, role="superadmin", is_active=True)
        a.set_password(pw)
        db.session.add(a); db.session.commit()
        print(f"[OK] Создан супер-админ: {a.username}")
PY

echo "[7/9] Проверяю/создаю systemd-сервис..."
sudo tee /etc/systemd/system/openvpn-admin.service >/dev/null <<EOF
[Unit]
Description=OpenVPN Admin Panel
After=network.target

[Service]
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python $APP_DIR/app.py
Restart=always
User=root
Environment=PYTHONUNBUFFERED=1
StandardOutput=append:$APP_DIR/logs/webadmin.log
StandardError=append:$APP_DIR/logs/webadmin.log

[Install]
WantedBy=multi-user.target
EOF

echo "[8/9] Перезапускаю сервис..."
sudo systemctl daemon-reload
sudo systemctl enable --now openvpn-admin
sleep 1
sudo systemctl --no-pager --full status openvpn-admin || true

echo "[9/9] ✅ Обновление завершено! Открой http://<IP>:5000 и проверь панель администратора."

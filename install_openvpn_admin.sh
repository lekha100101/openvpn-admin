#!/usr/bin/env bash
set -euo pipefail

# ========= ПАРАМЕТРЫ =========
APP_DIR="/opt/openvpn_admin_panel"
REPO_URL="https://github.com/lekha100101/openvpn-admin.git"
RELEASE="${RELEASE:-}"              # например: export RELEASE=v1.1.0 ; пусто = main
PY_BIN="${PY_BIN:-python3}"

echo "[1/8] Установка системных зависимостей..."
if command -v dnf >/dev/null 2>&1; then
  sudo dnf -y install python3 python3-pip git sqlite
elif command -v yum >/dev/null 2>&1; then
  sudo yum -y install python3 python3-pip git sqlite
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y python3 python3-venv python3-pip git sqlite3
else
  echo "Неизвестный пакетный менеджер. Установи python3, pip, git, sqlite вручную." >&2
fi

echo "[2/8] Клонирование/обновление репозитория..."
sudo mkdir -p "$APP_DIR"
sudo chown -R "$USER":"$USER" "$APP_DIR"
cd "$APP_DIR"

if [ ! -d .git ]; then
  git clone "$REPO_URL" "$APP_DIR"
else
  git remote -v >/dev/null || { echo "Папка есть, но не git. Перемести/очисти $APP_DIR" >&2; exit 1; }
  git fetch --all --tags
fi

if [ -n "$RELEASE" ]; then
  echo "[checkout] tag/branch: $RELEASE"
  git checkout "$RELEASE"
else
  echo "[checkout] main"
  git checkout main
  git pull --ff-only origin main || true
fi

echo "[3/8] Виртуальное окружение (.venv)..."
$PY_BIN -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "[4/8] Подготовка каталогов (instance, logs)..."
mkdir -p instance logs

echo "[5/8] Инициализация БД (создание таблиц)..."
python - <<'PY'
from app import create_app
from extensions import db
app = create_app()
with app.app_context():
    db.create_all()
print("[OK] db.create_all() выполнен")
PY

echo "[6/8] Создание/обновление супер-админа..."
# Скрипт интерактивный — попросит логин/пароль и назначит роль superadmin
python setup_admin.py

echo "[7/8] Создание systemd сервиса..."
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
# Логи в файл приложения (app сам пишет в logs/webadmin.log); systemd тоже туда продублируем:
StandardOutput=append:$APP_DIR/logs/webadmin.log
StandardError=append:$APP_DIR/logs/webadmin.log

[Install]
WantedBy=multi-user.target
EOF

echo "[8/8] Перезапуск systemd и запуск сервиса..."
sudo systemctl daemon-reload
sudo systemctl enable --now openvpn-admin
sleep 1
sudo systemctl --no-pager --full status openvpn-admin || true

echo "Готово. Открой http://<IP-сервера>:5000 и войди под супер-админом."

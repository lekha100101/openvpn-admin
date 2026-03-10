#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/openvpn_admin_panel}"
REPO_URL="${REPO_URL:-https://github.com/lekha100101/openvpn-admin.git}"
BRANCH="${BRANCH:-main}"
RELEASE="${RELEASE:-}"                      # optional tag/branch override
PY_BIN="${PY_BIN:-python3}"
SERVICE_NAME="${SERVICE_NAME:-openvpn-admin}"
BACKUP_DIR="${BACKUP_DIR:-/root/ovpn_admin_backups}"
OVERWRITE_CONFIG="${OVERWRITE_CONFIG:-0}"    # 1 = overwrite config.py

step() { echo; echo "[$1] $2"; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "❌ Missing command: $1"; exit 1; }; }

step "0/9" "Installing system dependencies"
if command -v dnf >/dev/null 2>&1; then
  sudo dnf -y install python3 python3-pip python3-virtualenv git sqlite rsync tar >/dev/null
elif command -v yum >/dev/null 2>&1; then
  sudo yum -y install python3 python3-pip git sqlite rsync tar >/dev/null
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y >/dev/null
  sudo apt-get install -y python3 python3-venv python3-pip git sqlite3 rsync tar >/dev/null
else
  echo "❌ Unsupported package manager. Install python3, pip, git, sqlite, rsync, tar manually."
  exit 1
fi

need_cmd git
need_cmd rsync
need_cmd tar
need_cmd "$PY_BIN"

step "1/9" "Preparing directories"
sudo mkdir -p "$APP_DIR" "$BACKUP_DIR"
sudo chown -R "$USER:$USER" "$APP_DIR"
mkdir -p "$APP_DIR/instance" "$APP_DIR/logs"

step "2/9" "Creating backup"
STAMP="$(date +%F_%H%M%S)"
BACKUP_PATH="$BACKUP_DIR/backup_${STAMP}.tgz"
sudo tar -czf "$BACKUP_PATH" --exclude='.venv' --exclude='.git' -C "$APP_DIR" . || true
echo "✅ Backup: $BACKUP_PATH"

step "3/9" "Fetching latest sources"
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" fetch --all --tags
  if [ -n "$RELEASE" ]; then
    git -C "$APP_DIR" checkout "$RELEASE"
  else
    git -C "$APP_DIR" checkout "$BRANCH"
    git -C "$APP_DIR" pull --ff-only origin "$BRANCH"
  fi
else
  if [ -n "$(find "$APP_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    echo "❌ $APP_DIR exists but is not a git repo and not empty. Move its content and retry."
    exit 1
  fi
  if [ -n "$RELEASE" ]; then
    git clone --branch "$RELEASE" --depth 1 "$REPO_URL" "$APP_DIR"
  else
    git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$APP_DIR"
  fi
fi

step "4/9" "Synchronizing tracked files"
if [ "$OVERWRITE_CONFIG" != "1" ] && [ -f "$APP_DIR/config.py" ]; then
  git -C "$APP_DIR" checkout -- . ':!config.py' || true
  git -C "$APP_DIR" clean -fd -e instance -e logs -e .venv -e config.py || true
  echo "⚙️ Kept local config.py (set OVERWRITE_CONFIG=1 to overwrite)."
else
  git -C "$APP_DIR" checkout -- . || true
  git -C "$APP_DIR" clean -fd -e instance -e logs -e .venv || true
fi

# Keep locally customized client template if it already exists
if [ -f "$APP_DIR/client-template.ovpn" ] && [ "$OVERWRITE_CONFIG" != "1" ]; then
  cp "$APP_DIR/client-template.ovpn" "$TMP_DIR/client-template.ovpn.bak"
  git -C "$APP_DIR" checkout -- client-template.ovpn || true
  cp "$TMP_DIR/client-template.ovpn.bak" "$APP_DIR/client-template.ovpn"
  echo "⚙️ Kept local client-template.ovpn"
fi

step "5/9" "Updating Python environment"
cd "$APP_DIR"
if ! "$PY_BIN" -m venv .venv >/dev/null 2>&1; then
  "$PY_BIN" -m pip install --user --upgrade virtualenv >/dev/null
  "$PY_BIN" -m virtualenv .venv >/dev/null
fi
# shellcheck source=/dev/null
source .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt >/dev/null

step "6/9" "Applying DB migrations"
python - <<'PY'
import sqlite3
from app import create_app
from extensions import db

app = create_app()
with app.app_context():
    db.create_all()

db_path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
con = sqlite3.connect(db_path)
cur = con.cursor()

def table_exists(name):
    cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None

def add_col_if_missing(table, col_name, ddl):
    cur.execute(f"PRAGMA table_info({table})")
    cols = {row[1] for row in cur.fetchall()}
    if col_name not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")

if table_exists("admin"):
    add_col_if_missing("admin", "role", "role TEXT DEFAULT 'admin'")
    add_col_if_missing("admin", "is_active", "is_active INTEGER DEFAULT 1")
    add_col_if_missing("admin", "last_login_at", "last_login_at TEXT")

if not table_exists("audit_log"):
    cur.execute('''
        CREATE TABLE audit_log (
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
        )
    ''')

cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)")
cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)")
cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_admin ON audit_log(admin_id)")
con.commit()
con.close()
print("[OK] DB migration done")
PY

step "7/9" "Ensuring superadmin account"
if [ -n "${SUPERADMIN_USER:-}" ] && [ -n "${SUPERADMIN_PASS:-}" ]; then
  SUPERADMIN_USER="$SUPERADMIN_USER" SUPERADMIN_PASS="$SUPERADMIN_PASS" python - <<'PY'
import os
from app import create_app
from extensions import db
from models import Admin

user = os.environ["SUPERADMIN_USER"].strip()
pw = os.environ["SUPERADMIN_PASS"]

app = create_app()
with app.app_context():
    db.create_all()
    a = Admin.query.filter_by(username=user).first()
    if not a:
      a = Admin(username=user, role='superadmin', is_active=True)
      db.session.add(a)
    a.set_password(pw)
    a.role = 'superadmin'
    a.is_active = True
    db.session.commit()
print(f"[OK] superadmin ensured: {user}")
PY
else
  echo "⚠️ SUPERADMIN_USER/SUPERADMIN_PASS not provided: skipped password rotation."
  echo "   Run: cd $APP_DIR && source .venv/bin/activate && python setup_admin.py"
fi

step "8/9" "Updating and restarting systemd service"
sudo tee "/etc/systemd/system/${SERVICE_NAME}.service" >/dev/null <<EOF_SERVICE
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
EOF_SERVICE

sudo systemctl daemon-reload
sudo systemctl enable --now "$SERVICE_NAME"
sleep 1
sudo systemctl --no-pager --full status "$SERVICE_NAME" || true

step "9/9" "Done"
echo "✅ Update complete. App dir: $APP_DIR"

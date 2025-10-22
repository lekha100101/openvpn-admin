from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime
from extensions import db

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(150), unique=True, nullable=False)
    password_hash= db.Column(db.String(256), nullable=False)
    role         = db.Column(db.String(32), nullable=False, default='admin')  # 'superadmin'|'admin'|'viewer'
    is_active    = db.Column(db.Boolean, nullable=False, default=True)
    last_login_at= db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Branch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class VPNUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    first_name = db.Column(db.String(150), nullable=True)
    last_name = db.Column(db.String(150), nullable=True)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'))
    branch = db.relationship('Branch', backref='users')
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# === Журнал действий администраторов ===
class AuditLog(db.Model):
    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)  # ← важно: Integer + autoincrement
    admin_id    = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)
    username    = db.Column(db.String(150), nullable=True)
    action      = db.Column(db.String(128), nullable=False)
    target_type = db.Column(db.String(64), nullable=True)
    target_id   = db.Column(db.String(128), nullable=True)
    status      = db.Column(db.String(16), nullable=False)
    details     = db.Column(db.Text, nullable=True)
    ip_address  = db.Column(db.String(64), nullable=True)
    user_agent  = db.Column(db.Text, nullable=True)
    created_at  = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

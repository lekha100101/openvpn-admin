from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, abort
from flask_login import login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import datetime, socket, io, os, logging
from logging.handlers import RotatingFileHandler
from extensions import db, login_manager
from config import Config

def log_auth_attempt(timestamp, username, ip, result):
    log_line = f"[{timestamp}] User: {username} | IP: {ip} | Result: {result}\n"
    with open("auth.log", "a") as log_file:
        log_file.write(log_line)

def create_app():
    import os
    app = Flask(__name__)
    app.config.from_object(Config)

    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, "data.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path
    app.logger.info(f"DB path set to {db_path}")

    # Передаём APP_TITLE во все шаблоны
    app.jinja_env.globals.update(APP_TITLE=app.config.get("APP_TITLE", "OpenVPN Admin"))

    # === Файловый логгер веб-панели ===
    os.makedirs(app.config['LOG_DIR'], exist_ok=True)
    log_path = os.path.join(app.config['LOG_DIR'], app.config['LOG_FILE'])
    _handler = RotatingFileHandler(log_path, maxBytes=10*1024*1024, backupCount=5)
    _handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    _handler.setLevel(logging.INFO)
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(_handler)

    limiter = Limiter(get_remote_address, default_limits=["200 per day", "50 per hour"])
    limiter.init_app(app)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    from models import Admin, VPNUser, Branch
    from models import AuditLog

    # === RBAC: требование роли ===
    def require_role(*roles):
        def wrapper(fn):
            from functools import wraps
            @wraps(fn)
            def inner(*args, **kwargs):
                if not current_user.is_authenticated:
                    return login_manager.unauthorized()
                if not getattr(current_user, "is_active", True):
                    abort(401)
                if roles and getattr(current_user, "role", "viewer") not in roles:
                    abort(403)
                return fn(*args, **kwargs)
            return inner
        return wrapper

    # === Аудит действий в БД + файл ===
    def audit(action, target_type=None, target_id_getter=None):
        """
        action: str - код действия (например 'vpn.user.create')
        target_type: str|None
        target_id_getter: callable(view_args, form, json) -> str|None
        """
        def decorator(fn):
            from functools import wraps
            @wraps(fn)
            def inner(*args, **kwargs):
                ip = request.headers.get('X-Forwarded-For', request.remote_addr)
                ua = request.headers.get('User-Agent', '')
                username = getattr(current_user, 'username', None)
                admin_id = getattr(current_user, 'id', None)
                _target_type = target_type
                _target_id = None
                try:
                    result = fn(*args, **kwargs)
                    status = 'success'
                    return result
                except Exception as e:
                    status = 'error'
                    app.logger.exception("Action failed: %s", action)
                    raise
                finally:
                    try:
                        if callable(target_id_getter):
                            _target_id = target_id_getter(request.view_args or {}, request.form, request.get_json(silent=True))
                        al = AuditLog(
                            admin_id=admin_id, username=username, action=action,
                            target_type=_target_type, target_id=_target_id,
                            status=status, details=None if status=='success' else 'error',
                            ip_address=ip, user_agent=ua
                        )
                        db.session.add(al)
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
                    app.logger.info("AUDIT action=%s user=%s status=%s ip=%s ua=%s target=%s:%s",
                                    action, username, status, ip, ua, _target_type, _target_id)
            return inner
        return decorator

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(Admin, int(user_id))

    @limiter.limit(app.config['LOGIN_RATE_LIMIT'])
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            admin = Admin.query.filter_by(username=username).first()
            if admin and admin.check_password(password):
                if not getattr(admin, 'is_active', True):
                    flash('Учетная запись администратора отключена.', 'danger')
                    return redirect(url_for('login'))
                login_user(admin)
                admin.last_login_at = datetime.datetime.utcnow()
                db.session.commit()
                app.logger.info("Admin login: %s", username)
                flash('Вы успешно вошли в систему.', 'success')
                return redirect(url_for('users'))
            else:
                flash('Неверный логин или пароль.', 'danger')
                return redirect(url_for('login'))
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Вы вышли из системы.', 'info')
        return redirect(url_for('login'))

    @app.route('/users', methods=['GET', 'POST'])
    @login_required
    def users():
        if request.method == 'POST':
            # требуется роль 'admin' или 'superadmin' для создания
            if not (current_user.is_authenticated and current_user.role in ('admin','superadmin')):
                abort(403)
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            username = request.form['username']
            password = request.form['password']
            branch_id = request.form.get('branch_id') or None

            if not password:
                flash('Пароль не может быть пустым.', 'danger')
                return redirect(url_for('users'))

            if VPNUser.query.filter_by(username=username).first():
                flash('Пользователь с таким логином уже существует.', 'danger')
                return redirect(url_for('users'))

            new_user = VPNUser(username=username, first_name=first_name, last_name=last_name, branch_id=branch_id)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            # аудит
            try:
                db.session.add(AuditLog(
                    admin_id=current_user.id, username=current_user.username,
                    action='vpn.user.create', target_type='vpn_user',
                    target_id=str(new_user.username), status='success',
                    ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()
            app.logger.info("AUDIT action=vpn.user.create user=%s target=vpn_user:%s", current_user.username, new_user.username)
            flash('Пользователь успешно добавлен.', 'success')
            return redirect(url_for('users'))

        return render_template('users.html', users=VPNUser.query.all(), branches=Branch.query.all())

    @app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
    @login_required
    def edit_user(user_id):
        user = VPNUser.query.get_or_404(user_id)
        branches = Branch.query.all()

        if request.method == 'POST':
            user.first_name = request.form['first_name']
            user.last_name = request.form['last_name']
            user.username = request.form['username']
            password = request.form['password']
            user.branch_id = request.form.get('branch_id') or None
            if password:
                user.set_password(password)
            db.session.commit()
            try:
                db.session.add(AuditLog(
                    admin_id=current_user.id, username=current_user.username,
                    action='vpn.user.update', target_type='vpn_user',
                    target_id=str(user.username), status='success',
                    ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()
            flash('Данные пользователя обновлены.', 'success')
            return redirect(url_for('users'))

        return render_template('edit_user.html', user=user, branches=branches)

    @app.route('/delete_user/<int:user_id>', methods=['POST'])
    @login_required
    def delete_user(user_id):
        user = VPNUser.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        try:
            db.session.add(AuditLog(
                admin_id=current_user.id, username=current_user.username,
                action='vpn.user.delete', target_type='vpn_user', target_id=str(user.username),
                status='success', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
        flash('Пользователь удалён.', 'success')
        return redirect(url_for('users'))

    @app.route('/branches', methods=['GET', 'POST'])
    @login_required
    def branches():
        if request.method == 'POST':
            name = request.form['name']
            if Branch.query.filter_by(name=name).first():
                flash('Филиал с таким именем уже существует.', 'danger')
                return redirect(url_for('branches'))
            db.session.add(Branch(name=name))
            db.session.commit()
            try:
                db.session.add(AuditLog(
                    admin_id=current_user.id, username=current_user.username,
                    action='branch.create', target_type='branch', target_id=name,
                    status='success', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()
            flash('Филиал успешно добавлен.', 'success')
            return redirect(url_for('branches'))
        return render_template('branches.html', branches=Branch.query.all())

    @app.route('/edit_branch/<int:branch_id>', methods=['GET', 'POST'])
    @login_required
    def edit_branch(branch_id):
        branch = Branch.query.get_or_404(branch_id)
        if request.method == 'POST':
            branch.name = request.form['name']
            db.session.commit()
            try:
                db.session.add(AuditLog(
                    admin_id=current_user.id, username=current_user.username,
                    action='branch.update', target_type='branch', target_id=str(branch.name),
                    status='success', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()
            flash('Название филиала обновлено.', 'success')
            return redirect(url_for('branches'))
        return render_template('edit_branch.html', branch=branch)

    @app.route('/delete_branch/<int:branch_id>', methods=['POST'])
    @login_required
    def delete_branch(branch_id):
        branch = Branch.query.get_or_404(branch_id)
        if branch.users:
            flash('Нельзя удалить филиал, к которому привязаны пользователи.', 'danger')
            return redirect(url_for('branches'))
        db.session.delete(branch)
        db.session.commit()
        try:
            db.session.add(AuditLog(
                admin_id=current_user.id, username=current_user.username,
                action='branch.delete', target_type='branch', target_id=str(branch.name),
                status='success', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
        flash('Филиал удалён.', 'success')
        return redirect(url_for('branches'))

    @app.route('/')
    def index():
        return redirect(url_for('users'))

    @app.route('/api/authenticate', methods=['POST'])
    def api_authenticate():
        username = request.form.get('username')
        password = request.form.get('password')
        client_ip = request.remote_addr
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if not username or not password:
            log_auth_attempt(now, username or "UNKNOWN", client_ip, "Missing credentials")
            return "Missing credentials", 400

        user = VPNUser.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            log_auth_attempt(now, username, client_ip, "Success")
            return "OK", 200
        else:
            log_auth_attempt(now, username, client_ip, "Failed")
            return "Unauthorized", 401

    @app.route('/connections')
    @login_required
    def connections():
        connections = []
        try:
            with open(app.config['OVPN_STATUS_LOG']) as f:
                for line in f:
                    if line.startswith('CLIENT_LIST'):
                        parts = line.strip().split(',')
                        connections.append({
                            'username': parts[1],
                            'real_ip': parts[2],
                            'vpn_ip': parts[3],
                            'bytes_received': parts[4],
                            'bytes_sent': parts[5],
                            'connected_since': parts[7],
                        })
        except Exception as e:
            flash(f"Ошибка чтения статуса OpenVPN: {str(e)}", "danger")
        return render_template('connections.html', connections=connections)

    @app.route('/api/connections')
    @login_required
    def api_connections():
        connections = []
        try:
            with open(app.config['OVPN_STATUS_LOG']) as f:
                for line in f:
                    if line.startswith('CLIENT_LIST'):
                        parts = line.strip().split(',')
                        connections.append({
                            'username': parts[1],
                            'real_ip': parts[2],
                            'vpn_ip': parts[3],
                            'bytes_received': parts[4],
                            'bytes_sent': parts[5],
                            'connected_since': parts[7],
                        })
        except Exception as e:
            return {"error": str(e)}, 500
        return {"connections": connections}

    @app.route('/toggle_user/<int:user_id>', methods=['POST'])
    @login_required
    def toggle_user(user_id):
        user = VPNUser.query.get_or_404(user_id)
        user.is_active = not user.is_active
        db.session.commit()
        try:
            db.session.add(AuditLog(
                admin_id=current_user.id, username=current_user.username,
                action='vpn.user.toggle', target_type='vpn_user', target_id=str(user.username),
                status='success', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
        return redirect(url_for('users'))

    @app.route('/api/kill/<username>', methods=['POST'])
    @login_required
    def kill_connection(username):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', 7505))
            s.sendall(f"kill {username}\n".encode())
            s.sendall(b"quit\n")
            s.close()
            try:
                db.session.add(AuditLog(
                    admin_id=current_user.id, username=current_user.username,
                    action='vpn.kill', target_type='vpn_session', target_id=username,
                    status='success', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()
            return {"status": "success", "message": f"Пользователь {username} отключён"}, 200
        except Exception as e:
            return {"status": "error", "message": str(e)}, 500

    @app.route('/download-config')
    @login_required
    def download_config_template():
        try:
            with open(app.config['OVPN_TEMPLATE_PATH'], "r") as f:
                content = f.read()
        except FileNotFoundError:
            return "Конфигурационный файл не найден", 404

        try:
            if current_user.is_authenticated:
                db.session.add(AuditLog(
                    admin_id=current_user.id, username=current_user.username,
                    action='config.download', target_type='config', target_id='client-template.ovpn',
                    status='success', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')
                ))
                db.session.commit()
        except Exception:
            db.session.rollback()

        return send_file(io.BytesIO(content.encode()),
                         as_attachment=True,
                         download_name="client-config.ovpn",
                         mimetype='application/octet-stream')

    # ===== Администраторы =====
    @app.route('/admins', methods=['GET', 'POST'])
    @login_required
    @require_role('superadmin')
    def admins():
        if request.method == 'POST':
            username = request.form['username'].strip()
            password = request.form['password'].strip()
            role     = request.form.get('role','admin')
            if not username or not password or role not in ('viewer','admin','superadmin'):
                flash('Проверьте поля формы.', 'danger'); return redirect(url_for('admins'))
            if Admin.query.filter_by(username=username).first():
                flash('Администратор уже существует.', 'danger'); return redirect(url_for('admins'))
            a = Admin(username=username, role=role, is_active=True)
            a.set_password(password)
            db.session.add(a); db.session.commit()
            try:
                db.session.add(AuditLog(admin_id=current_user.id, username=current_user.username,
                                        action='admin.create', target_type='admin', target_id=username,
                                        status='success', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')))
                db.session.commit()
            except Exception: db.session.rollback()
            flash('Администратор создан.', 'success'); return redirect(url_for('admins'))
        return render_template('admins.html', admins=Admin.query.order_by(Admin.id.desc()).all())

    @app.route('/admins/<int:admin_id>/toggle', methods=['POST'])
    @login_required
    @require_role('superadmin')
    def admin_toggle(admin_id):
        a = Admin.query.get_or_404(admin_id)
        if a.id == current_user.id:
            flash('Нельзя отключить самого себя.', 'warning'); return redirect(url_for('admins'))
        a.is_active = not a.is_active; db.session.commit()
        try:
            db.session.add(AuditLog(admin_id=current_user.id, username=current_user.username,
                                    action='admin.toggle', target_type='admin', target_id=str(admin_id),
                                    status='success', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')))
            db.session.commit()
        except Exception: db.session.rollback()
        flash('Статус обновлён.', 'success'); return redirect(url_for('admins'))

    @app.route('/admins/<int:admin_id>/role', methods=['POST'])
    @login_required
    @require_role('superadmin')
    def admin_change_role(admin_id):
        a = Admin.query.get_or_404(admin_id)
        new_role = request.form.get('role','viewer')
        if new_role not in ('viewer','admin','superadmin'):
            flash('Недопустимая роль.', 'danger'); return redirect(url_for('admins'))
        a.role = new_role; db.session.commit()
        try:
            db.session.add(AuditLog(admin_id=current_user.id, username=current_user.username,
                                    action='admin.change_role', target_type='admin', target_id=str(admin_id),
                                    status='success', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')))
            db.session.commit()
        except Exception: db.session.rollback()
        flash('Роль обновлена.', 'success'); return redirect(url_for('admins'))

    @app.route('/admins/<int:admin_id>/reset_password', methods=['POST'])
    @login_required
    @require_role('superadmin')
    def admin_reset_password(admin_id):
        from secrets import token_urlsafe
        a = Admin.query.get_or_404(admin_id)
        temp_pass = token_urlsafe(12)
        a.set_password(temp_pass); db.session.commit()
        try:
            db.session.add(AuditLog(admin_id=current_user.id, username=current_user.username,
                                    action='admin.reset_password', target_type='admin', target_id=str(admin_id),
                                    status='success', ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent','')))
            db.session.commit()
        except Exception: db.session.rollback()
        flash(f'Временный пароль: {temp_pass}', 'warning'); return redirect(url_for('admins'))

    # ===== Аудит =====
    @app.route('/audit')
    @login_required
    @require_role('admin','superadmin')
    def audit_list():
        q = AuditLog.query.order_by(AuditLog.created_at.desc())
        action = request.args.get('action'); username = request.args.get('username'); status = request.args.get('status')
        if action:   q = q.filter(AuditLog.action.ilike(f'%{action}%'))
        if username: q = q.filter(AuditLog.username.ilike(f'%{username}%'))
        if status:   q = q.filter(AuditLog.status==status)
        rows = q.limit(2000).all()
        return render_template('audit_list.html', rows=rows)

    @app.route('/audit/export')
    @login_required
    @require_role('superadmin')
    def audit_export_csv():
        import csv, io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['created_at','username','action','target_type','target_id','status','ip_address','user_agent','details'])
        for r in AuditLog.query.order_by(AuditLog.created_at.desc()).all():
            writer.writerow([r.created_at, r.username, r.action, r.target_type, r.target_id, r.status, r.ip_address, (r.user_agent or '')[:200], (r.details or '')[:200]])
        from flask import Response
        return Response(output.getvalue(), mimetype='text/csv',
                        headers={'Content-Disposition':'attachment; filename=audit_export.csv'})

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000)


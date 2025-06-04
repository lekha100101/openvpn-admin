from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import datetime, socket, io
from extensions import db, login_manager
from config import Config

def log_auth_attempt(timestamp, username, ip, result):
    log_line = f"[{timestamp}] User: {username} | IP: {ip} | Result: {result}\n"
    with open("auth.log", "a") as log_file:
        log_file.write(log_line)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Передаём APP_TITLE во все шаблоны
    app.jinja_env.globals.update(APP_TITLE=app.config.get("APP_TITLE", "OpenVPN Admin"))

    limiter = Limiter(get_remote_address, default_limits=["200 per day", "50 per hour"])
    limiter.init_app(app)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    from models import Admin, VPNUser, Branch

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
                login_user(admin)
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
            flash('Данные пользователя обновлены.', 'success')
            return redirect(url_for('users'))

        return render_template('edit_user.html', user=user, branches=branches)

    @app.route('/delete_user/<int:user_id>', methods=['POST'])
    @login_required
    def delete_user(user_id):
        user = VPNUser.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
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

        return send_file(io.BytesIO(content.encode()),
                         as_attachment=True,
                         download_name="client-config.ovpn",
                         mimetype='application/octet-stream')

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000)


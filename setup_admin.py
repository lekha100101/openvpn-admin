# setup_admin.py
from getpass import getpass
from app import create_app
from extensions import db
from models import Admin

def main():
    app = create_app()
    with app.app_context():
        # Убедимся, что таблицы есть
        db.create_all()

        print("[INFO] Создание / обновление супер-администратора")
        username = input("Логин супер-администратора: ").strip()
        while not username:
            username = input("Логин не может быть пустым. Повторите: ").strip()

        # Пароль вводим без эха
        password = getpass("Пароль: ").strip()
        while not password:
            password = getpass("Пароль не может быть пустым. Повторите: ").strip()

        # Ищем существующего
        admin = Admin.query.filter_by(username=username).first()
        if admin:
            admin.set_password(password)
            admin.role = "superadmin"
            admin.is_active = True
            db.session.commit()
            print(f"[OK] Обновлён существующий админ '{username}' → роль=superadmin, активирован, пароль обновлён.")
        else:
            admin = Admin(username=username, role="superadmin", is_active=True)
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()
            print(f"[OK] Создан супер-админ '{username}'.")

        # На всякий случай покажем текущих админов
        rows = Admin.query.order_by(Admin.id.asc()).all()
        print("\n[INFO] Текущие администраторы:")
        for a in rows:
            print(f" - id={a.id}, username={a.username}, role={a.role}, is_active={a.is_active}")

if __name__ == "__main__":
    main()


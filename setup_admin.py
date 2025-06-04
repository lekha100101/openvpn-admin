import os
from app import create_app
from extensions import db
from models import Admin

app = create_app()

def setup_database():
    if not os.path.exists('data.db'):
        print("[INFO] База данных не найдена. Создаём новую...")
    else:
        print("[INFO] База данных найдена.")

    with app.app_context():
        db.create_all()

def create_or_update_admin():
    username = input("Введите логин администратора: ").strip()
    password = input("Введите пароль администратора: ").strip()

    with app.app_context():
        admin = Admin.query.filter_by(username=username).first()
        if admin:
            print(f"[INFO] Администратор '{username}' уже существует.")
            choice = input("Хотите обновить пароль? (y/n): ").strip().lower()
            if choice == 'y':
                admin.set_password(password)
                db.session.commit()
                print(f"[SUCCESS] Пароль администратора '{username}' обновлён.")
            else:
                print("[INFO] Пароль оставлен без изменений.")
        else:
            new_admin = Admin(username=username)
            new_admin.set_password(password)
            db.session.add(new_admin)
            db.session.commit()
            print(f"[SUCCESS] Администратор '{username}' создан.")

if __name__ == "__main__":
    setup_database()
    create_or_update_admin()


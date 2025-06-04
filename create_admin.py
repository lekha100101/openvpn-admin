from app import create_app
from extensions import db
from models import Admin

app = create_app()

with app.app_context():
    username = input("Введите логин администратора: ")
    password = input("Введите пароль администратора: ")

    existing = Admin.query.filter_by(username=username).first()
    if existing:
        print(f"Пользователь '{username}' уже существует.")
    else:
        admin = Admin(username=username)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print(f"Администратор '{username}' успешно создан!")


# config.py — единый файл конфигурации
import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change_this_default_secret")
    SQLALCHEMY_DATABASE_URI = "sqlite:///data.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOGIN_RATE_LIMIT = "5 per 10 minutes"

    # Пути к файлам и шаблонам
    OVPN_TEMPLATE_PATH = "client-template.ovpn"
    OVPN_LOG_PATH = "/var/log/openvpn/openvpn.log"
    OVPN_STATUS_LOG = "/var/log/openvpn/openvpn-status.log"

    # Название сайта
    APP_TITLE = "OpenVPN Admin Panel Жамбылская Область"

    # Дополнительно (если понадобится позже)
    # MAIL_SERVER = "smtp.example.com"
    # MAIL_PORT = 587
    # MAIL_USE_TLS = True
    # MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    # MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")


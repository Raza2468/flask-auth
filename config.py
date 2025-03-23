# config.py
import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Common session settings
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=300)

class DevelopmentConfig(Config):
    DEBUG = True
    # Development ke liye SQLite database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///flask_app.db'
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = 'None'

class ProductionConfig(Config):
    DEBUG = False
    # Production ke liye PostgreSQL database
    SQLALCHEMY_DATABASE_URI = (
        'postgresql+psycopg2://auth_user:auth_password@34.235.175.50:5432/auth_db?sslmode=disable'
    )
    # Agar aap production mein HTTPS use kar rahe hain to SESSION_COOKIE_SECURE ko True karen
    SESSION_COOKIE_SECURE = False  # Change to True if using HTTPS in production
    SESSION_COOKIE_SAMESITE = 'None'

    # Set to True if using HTTPS in production
    # SESSION_COOKIE_SECURE = False
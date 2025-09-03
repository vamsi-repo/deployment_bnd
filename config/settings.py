import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration class"""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24).hex())
    DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    ENV = os.getenv('FLASK_ENV', 'development')
    
    # Database Configuration for SQL Server
    DB_CONFIG = {
        'driver': os.getenv('DB_DRIVER', 'ODBC Driver 17 for SQL Server'),
        'server': os.getenv('DB_SERVER'),
        'database': os.getenv('DB_DATABASE'),
        'username': os.getenv('DB_USERNAME'),
        'password': os.getenv('DB_PASSWORD'),
        'trusted_connection': 'no',
        'encrypt': 'yes',
        'trust_server_certificate': 'yes'
    }
    
    # Session Configuration
    SESSION_TYPE = os.getenv('SESSION_TYPE', 'filesystem')
    SESSION_FILE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'sessions')
    SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
    SESSION_COOKIE_HTTPONLY = os.getenv('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    PERMANENT_SESSION_LIFETIME = int(os.getenv('PERMANENT_SESSION_LIFETIME', '86400'))
    
    # File Upload Configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'uploads')
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_FILE_SIZE', '16777216'))  # 16MB
    ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'xlsx,xls,csv,txt,dat').split(','))
    
    # CORS Configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3001,http://localhost:5173').split(',')
    
    # User Roles with numeric hierarchy (lower number = higher privilege)
    USER_ROLES = {
        'SUPER_ADMIN': 1,
        'ADMIN': 2,
        'MANAGER': 3,
        'USER': 4,
        'VIEWER': 5
    }
    
    # Role Permissions
    ROLE_PERMISSIONS = {
        'SUPER_ADMIN': ['*'],  # All permissions
        'ADMIN': [
            'user.create', 'user.read', 'user.update', 'user.delete',
            'template.create', 'template.read', 'template.update', 'template.delete',
            'validation.create', 'validation.read', 'validation.update', 'validation.delete',
            'file.upload', 'file.download', 'file.process',
            'role.manage'
        ],
        'MANAGER': [
            'user.read', 'user.update',
            'template.create', 'template.read', 'template.update',
            'validation.create', 'validation.read', 'validation.update',
            'file.upload', 'file.download', 'file.process'
        ],
        'USER': [
            'template.read', 'template.create',
            'validation.create', 'validation.read',
            'file.upload', 'file.download', 'file.process'
        ],
        'VIEWER': [
            'template.read',
            'validation.read',
            'file.download'
        ]
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    ENV = 'development'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    ENV = 'production'
    SESSION_COOKIE_SECURE = True
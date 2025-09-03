import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Configuration class for the application"""
    
    # Database configuration
    DATABASE_TYPE = os.environ.get('DATABASE_TYPE', 'sqlite')
    
    # SQLite configuration (for development/small deployments)
    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'keansa_test.db')
    
    # PostgreSQL configuration (for production on Railway)
    DATABASE_URL = os.environ.get('DATABASE_URL')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = os.environ.get('DB_PORT', '5432')
    DB_NAME = os.environ.get('DB_NAME', 'keansa_db')
    DB_USER = os.environ.get('DB_USER', 'postgres')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Session configuration
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = True
    SESSION_USE_SIGNER = True
    SESSION_FILE_DIR = os.environ.get('SESSION_FILE_DIR', './sessions')
    
    # Upload configuration
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', './uploads')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', str(16 * 1024 * 1024)))  # 16MB
    
    # CORS configuration
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # Environment
    ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')
    PORT = int(os.environ.get('PORT', 5000))
    
    # User roles hierarchy (lower number = higher privilege)
    USER_ROLES = {
        'SUPER_ADMIN': 1,
        'ADMIN': 2,
        'MANAGER': 3,
        'USER': 4,
        'VIEWER': 5
    }
    
    # Role-based permissions
    ROLE_PERMISSIONS = {
        'SUPER_ADMIN': ['*'],  # All permissions
        'ADMIN': [
            'user.create', 'user.read', 'user.update', 'user.delete',
            'template.create', 'template.read', 'template.update', 'template.delete',
            'validation.create', 'validation.read', 'validation.update', 'validation.delete',
            'file.upload', 'file.download', 'file.delete',
            'role.manage'
        ],
        'MANAGER': [
            'user.read', 'user.update',
            'template.create', 'template.read', 'template.update',
            'validation.create', 'validation.read', 'validation.update',
            'file.upload', 'file.download'
        ],
        'USER': [
            'template.read',
            'validation.create', 'validation.read',
            'file.upload', 'file.download'
        ],
        'VIEWER': [
            'template.read',
            'validation.read',
            'file.download'
        ]
    }
    
    @staticmethod
    def get_database_url():
        """Get the appropriate database URL based on environment"""
        if Config.DATABASE_URL:
            # Railway provides DATABASE_URL for PostgreSQL
            return Config.DATABASE_URL
        elif Config.DATABASE_TYPE.lower() == 'postgresql':
            # Manual PostgreSQL configuration
            return f"postgresql://{Config.DB_USER}:{Config.DB_PASSWORD}@{Config.DB_HOST}:{Config.DB_PORT}/{Config.DB_NAME}"
        else:
            # SQLite for development
            return f"sqlite:///{Config.DATABASE_PATH}"
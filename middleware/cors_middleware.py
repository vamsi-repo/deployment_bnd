from flask_cors import CORS
from config.settings import Config

def setup_cors(app):
    """Setup CORS configuration for the Flask app"""
    CORS(app, 
         supports_credentials=True, 
         origins=Config.CORS_ORIGINS,
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'])
    
    return app
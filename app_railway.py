import os
import logging
from flask import Flask, g, jsonify
from flask_session import Session
from dotenv import load_dotenv

# Load environment variables early
load_dotenv()

# Configure logging for Railway
logging.basicConfig(
    level=logging.INFO,  # Use INFO in production, not DEBUG
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler()]  # Only console output for Railway
)

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Basic Flask configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['DEBUG'] = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Session configuration
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_FILE_DIR'] = os.environ.get('SESSION_FILE_DIR', '/tmp/sessions')
    
    # Upload configuration
    app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', '/tmp/uploads')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
    
    # Ensure directories exist
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    except Exception as e:
        logging.warning(f"Directory creation warning: {e}")
    
    # Setup CORS
    try:
        from middleware.cors_middleware import setup_cors
        setup_cors(app)
    except Exception as e:
        logging.warning(f"CORS setup warning: {e}")
    
    # Setup Session
    try:
        Session(app)
    except Exception as e:
        logging.warning(f"Session setup warning: {e}")
    
    # Setup authentication middleware
    try:
        from middleware.auth_middleware import setup_auth_middleware
        setup_auth_middleware(app)
    except Exception as e:
        logging.warning(f"Auth middleware warning: {e}")
    
    # Database teardown
    @app.teardown_appcontext
    def close_db_connection(error):
        from database.connection import close_db
        close_db(error)
    
    # Register blueprints
    try:
        from controllers.auth_controller import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/api')
        logging.info("Auth controller registered")
    except Exception as e:
        logging.error(f"Failed to register auth controller: {e}")
    
    try:
        from controllers.template_controller import template_bp
        app.register_blueprint(template_bp, url_prefix='/api')
        logging.info("Template controller registered")
    except Exception as e:
        logging.warning(f"Template controller warning: {e}")
    
    try:
        from controllers.validation_controller import validation_bp
        app.register_blueprint(validation_bp, url_prefix='/api')
        logging.info("Validation controller registered")
    except Exception as e:
        logging.warning(f"Validation controller warning: {e}")
    
    try:
        from controllers.file_controller import file_bp
        app.register_blueprint(file_bp, url_prefix='/api')
        logging.info("File controller registered")
    except Exception as e:
        logging.warning(f"File controller warning: {e}")
    
    # Health check endpoint
    @app.route('/api/health', methods=['GET'])
    def health_check():
        return jsonify({'status': 'healthy', 'message': 'Keansa Data Validation API is running'})
    
    # Migration endpoint (for production)
    @app.route('/api/migrate', methods=['POST'])
    def run_migration():
        try:
            from database.migrations import init_db
            init_db()
            return jsonify({'status': 'success', 'message': 'Database migration completed successfully'})
        except Exception as e:
            logging.error(f"Migration failed: {str(e)}")
            return jsonify({'status': 'error', 'message': f'Migration failed: {str(e)}'}), 500
    
    # Default route
    @app.route('/')
    def home():
        return jsonify({'message': 'Keansa Data Validation API is running. Frontend should be served separately.'})
    
    logging.info("Flask app created successfully")
    return app

def initialize_database():
    """Initialize database with required tables and default data"""
    try:
        logging.info("Initializing database...")
        from database.migrations import init_db
        init_db()
        logging.info("Database initialization completed successfully")
    except Exception as e:
        logging.warning(f"Database initialization warning: {str(e)}")
        # Don't fail startup - database might already be initialized

# Create the application instance for gunicorn
app = create_app()

# Initialize database on app creation (for Railway)
try:
    with app.app_context():
        initialize_database()
except Exception as e:
    logging.warning(f"Startup database initialization failed: {e}")

if __name__ == '__main__':
    # This runs for local development
    port = int(os.environ.get('PORT', 5000))
    logging.info(f"Starting Flask server on port {port}")
    app.run(
        debug=app.config['DEBUG'],
        host='0.0.0.0',
        port=port
    )
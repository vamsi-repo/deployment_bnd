import os
import logging
from flask import Flask, g
from flask_session import Session
from dotenv import load_dotenv

# Import configurations and middleware
from config.settings import Config
from middleware.cors_middleware import setup_cors
from middleware.auth_middleware import setup_auth_middleware
from database.connection import close_db
from database.migrations import init_db

# Import controllers
from controllers.auth_controller import auth_bp
from controllers.template_controller import template_bp
from controllers.validation_controller import validation_bp
from controllers.file_controller import file_bp

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[logging.FileHandler('app.log'), logging.StreamHandler()]
)

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(Config)
    
    # Setup CORS
    setup_cors(app)
    
    # Setup Session
    Session(app)
    
    # Setup authentication middleware
    setup_auth_middleware(app)
    
    # Ensure directories exist
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    except OSError as e:
        logging.error(f"Failed to create directories: {e}")
        # Fallback to temp directories
        app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
        app.config['SESSION_FILE_DIR'] = '/tmp/sessions'
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    
    # Database teardown
    @app.teardown_appcontext
    def close_db_connection(error):
        close_db(error)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(template_bp, url_prefix='/api')
    app.register_blueprint(validation_bp, url_prefix='/api')
    app.register_blueprint(file_bp, url_prefix='/api')
    
    # Health check endpoint
    @app.route('/api/health', methods=['GET'])
    def health_check():
        return {'status': 'healthy', 'message': 'Keansa Data Validation API is running'}
    
    # Migration endpoint (for development)
    @app.route('/api/migrate', methods=['POST'])
    def run_migration():
        try:
            from database.connection import execute_query
            
            # Check if columns already exist
            check_query = "PRAGMA table_info(login_details)"
            result = execute_query(check_query, fetch_all=True)
            
            existing_columns = [row[1] for row in result]  # Column names are in index 1
            
            # Add is_approved column if it doesn't exist
            if 'is_approved' not in existing_columns:
                alter_query = "ALTER TABLE login_details ADD COLUMN is_approved INTEGER DEFAULT 0"
                execute_query(alter_query, commit=True)
                logging.info("Added is_approved column")
            
            # Add approved_by column if it doesn't exist
            if 'approved_by' not in existing_columns:
                alter_query = "ALTER TABLE login_details ADD COLUMN approved_by INTEGER"
                execute_query(alter_query, commit=True)
                logging.info("Added approved_by column")
            
            # Add approved_at column if it doesn't exist
            if 'approved_at' not in existing_columns:
                alter_query = "ALTER TABLE login_details ADD COLUMN approved_at DATETIME"
                execute_query(alter_query, commit=True)
                logging.info("Added approved_at column")
            
            # Update existing admin user to be approved
            update_admin_query = """
                UPDATE login_details 
                SET is_approved = 1 
                WHERE role IN ('SUPER_ADMIN', 'ADMIN')
            """
            execute_query(update_admin_query, commit=True)
            logging.info("Updated admin users to approved status")
            
            # Update existing regular users to be approved (for existing users)
            update_users_query = """
                UPDATE login_details 
                SET is_approved = 1 
                WHERE is_approved IS NULL OR is_approved = 0
            """
            execute_query(update_users_query, commit=True)
            logging.info("Updated existing users to approved status")
            
            return {'status': 'success', 'message': 'Database migration completed successfully'}
        except Exception as e:
            logging.error(f"Migration failed: {str(e)}")
            return {'status': 'error', 'message': f'Migration failed: {str(e)}'}, 500
    
    # Default route
    @app.route('/')
    def home():
        return {'message': 'Keansa Data Validation API is running. Frontend should be served separately.'}
    
    return app

def initialize_database():
    """Initialize database with required tables and default data"""
    try:
        logging.info("Initializing database...")
        init_db()
        logging.info("Database initialization completed successfully")
    except Exception as e:
        logging.error(f"Failed to initialize database: {str(e)}")
        raise

if __name__ == '__main__':
    app = create_app()
    
    # Initialize database on startup
    with app.app_context():
        initialize_database()
    
    # Start the application
    port = int(os.environ.get('PORT', 5000))
    logging.info(f"Starting Flask server on port {port}")
    app.run(
        debug=app.config['DEBUG'],
        host='0.0.0.0',
        port=port
    )
else:
    # For gunicorn/production - create app instance at module level
    app = create_app()
    
    # Initialize database
    try:
        with app.app_context():
            initialize_database()
    except Exception as e:
        logging.warning(f"Database initialization warning during app creation: {e}")
import logging
import bcrypt
import json
import os
from database.connection import execute_query, check_table_exists, USE_SQLITE, USE_POSTGRESQL

def create_tables():
    """Create all required tables for the application"""
    try:
        if USE_POSTGRESQL:
            tables = get_postgresql_tables()
        elif USE_SQLITE:
            tables = get_sqlite_tables()
        else:
            tables = get_sqlite_tables()  # Default fallback
        
        for table_sql in tables:
            try:
                execute_query(table_sql, commit=True)
                logging.info("Table processed successfully")
            except Exception as e:
                logging.warning(f"Table creation warning (might already exist): {e}")
                # Don't raise - table might already exist
                
        logging.info("Database tables initialization completed")
        
    except Exception as e:
        logging.error(f"Failed to create tables: {str(e)}")
        raise

def get_postgresql_tables():
    """Get PostgreSQL table creation statements"""
    return [
        # Users table with role-based access
        """
        CREATE TABLE IF NOT EXISTS login_details (
            id SERIAL PRIMARY KEY,
            first_name VARCHAR(100),
            last_name VARCHAR(100),
            email VARCHAR(255) UNIQUE NOT NULL,
            mobile VARCHAR(15),
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'USER',
            is_active INTEGER DEFAULT 1,
            is_approved INTEGER DEFAULT 0,
            approved_by INTEGER,
            approved_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            FOREIGN KEY (approved_by) REFERENCES login_details(id)
        )
        """,
        
        # Excel templates table
        """
        CREATE TABLE IF NOT EXISTS excel_templates (
            template_id SERIAL PRIMARY KEY,
            template_name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER NOT NULL,
            sheet_name VARCHAR(255),
            headers TEXT,
            status VARCHAR(20) DEFAULT 'ACTIVE',
            is_corrected INTEGER DEFAULT 0,
            remote_file_path VARCHAR(512),
            validation_frequency VARCHAR(20),
            first_identified_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES login_details(id) ON DELETE CASCADE
        )
        """,
        
        # User roles table
        """
        CREATE TABLE IF NOT EXISTS user_roles (
            role_id SERIAL PRIMARY KEY,
            role_name VARCHAR(50) UNIQUE NOT NULL,
            role_description VARCHAR(255),
            permissions TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    ]

def get_sqlite_tables():
    """Get SQLite table creation statements"""
    return [
        # Users table with role-based access
        """
        CREATE TABLE IF NOT EXISTS login_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT,
            last_name TEXT,
            email TEXT UNIQUE NOT NULL,
            mobile TEXT,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'USER',
            is_active INTEGER DEFAULT 1,
            is_approved INTEGER DEFAULT 0,
            approved_by INTEGER,
            approved_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            FOREIGN KEY (approved_by) REFERENCES login_details(id)
        )
        """,
        
        # Excel templates table
        """
        CREATE TABLE IF NOT EXISTS excel_templates (
            template_id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER NOT NULL,
            sheet_name TEXT,
            headers TEXT,
            status TEXT DEFAULT 'ACTIVE',
            is_corrected INTEGER DEFAULT 0,
            remote_file_path TEXT,
            validation_frequency TEXT,
            first_identified_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES login_details(id) ON DELETE CASCADE
        )
        """,
        
        # User roles table
        """
        CREATE TABLE IF NOT EXISTS user_roles (
            role_id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_name TEXT UNIQUE NOT NULL,
            role_description TEXT,
            permissions TEXT,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    ]

def create_admin_user():
    """Create default admin user if not exists"""
    try:
        # Check if admin user exists
        check_query = "SELECT COUNT(*) FROM login_details WHERE email = %s" if USE_POSTGRESQL else "SELECT COUNT(*) FROM login_details WHERE email = ?"
        result = execute_query(check_query, ('admin@keansa.com',), fetch_one=True)
        
        user_count = result['count'] if USE_POSTGRESQL and isinstance(result, dict) else result[0]
        
        if user_count == 0:
            admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            if USE_POSTGRESQL:
                insert_query = """
                    INSERT INTO login_details (first_name, last_name, email, mobile, password, role, is_active, is_approved)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
            else:
                insert_query = """
                    INSERT INTO login_details (first_name, last_name, email, mobile, password, role, is_active, is_approved)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """
            
            execute_query(
                insert_query,
                ('Admin', 'User', 'admin@keansa.com', '1234567890', admin_password, 'SUPER_ADMIN', 1, 1),
                commit=True
            )
            logging.info("Admin user created successfully")
        else:
            logging.info("Admin user already exists")
            
    except Exception as e:
        logging.warning(f"Admin user creation warning: {str(e)}")
        # Don't fail startup if admin creation fails

def create_default_roles():
    """Create default user roles"""
    try:
        from config.settings import Config
        
        # Check if roles table has data
        check_query = "SELECT COUNT(*) FROM user_roles"
        result = execute_query(check_query, fetch_one=True)
        
        role_count = result['count'] if USE_POSTGRESQL and isinstance(result, dict) else result[0]
        
        if role_count == 0:
            default_roles = [
                ('SUPER_ADMIN', 'Super Administrator with all permissions', json.dumps(['*'])),
                ('ADMIN', 'Administrator with most permissions', json.dumps(Config.ROLE_PERMISSIONS['ADMIN'])),
                ('MANAGER', 'Manager with limited admin permissions', json.dumps(Config.ROLE_PERMISSIONS['MANAGER'])),
                ('USER', 'Regular user with basic permissions', json.dumps(Config.ROLE_PERMISSIONS['USER'])),
                ('VIEWER', 'Read-only access user', json.dumps(Config.ROLE_PERMISSIONS['VIEWER']))
            ]
            
            if USE_POSTGRESQL:
                insert_query = """
                    INSERT INTO user_roles (role_name, role_description, permissions)
                    VALUES (%s, %s, %s)
                """
            else:
                insert_query = """
                    INSERT INTO user_roles (role_name, role_description, permissions)
                    VALUES (?, ?, ?)
                """
            
            for role_name, description, permissions in default_roles:
                execute_query(insert_query, (role_name, description, permissions), commit=True)
            
            logging.info("Default roles created successfully")
        else:
            logging.info("User roles already exist")
            
    except Exception as e:
        logging.warning(f"Default roles creation warning: {str(e)}")
        # Don't fail startup

def create_default_validation_rules():
    """Create default validation rules - skip for now during auth testing"""
    logging.info("Skipping validation rules creation for authentication testing")
    pass

def init_db():
    """Initialize the entire database"""
    try:
        create_tables()
        create_default_roles()
        create_admin_user()
        create_default_validation_rules()
        logging.info("Database initialization completed")
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")
        # Don't raise - let the app start even if DB init fails partially
        logging.warning("App will continue startup despite database initialization issues")

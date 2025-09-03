import logging
import bcrypt
import json
from database.connection import execute_query, check_table_exists, USE_SQLITE

def create_tables():
    """Create all required tables for the application"""
    try:
        if USE_SQLITE:
            tables = get_sqlite_tables()
        else:
            tables = get_sqlserver_tables()
        
        for table_sql in tables:
            try:
                execute_query(table_sql, commit=True)
                logging.info(f"Table processed successfully")
            except Exception as e:
                logging.error(f"Error creating table: {e}")
                raise
                
        logging.info("All database tables initialized successfully")
        
    except Exception as e:
        logging.error(f"Failed to create tables: {str(e)}")
        raise

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

def get_sqlserver_tables():
    """Get SQL Server table creation statements"""
    return [
        # Users table with role-based access
        """
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='login_details' AND xtype='U')
        CREATE TABLE login_details (
            id INT IDENTITY(1,1) PRIMARY KEY,
            first_name NVARCHAR(100),
            last_name NVARCHAR(100),
            email NVARCHAR(255) UNIQUE NOT NULL,
            mobile NVARCHAR(15),
            password NVARCHAR(255) NOT NULL,
            role NVARCHAR(50) DEFAULT 'USER',
            is_active BIT DEFAULT 1,
            created_at DATETIME2 DEFAULT GETDATE(),
            updated_at DATETIME2 DEFAULT GETDATE(),
            last_login DATETIME2
        )
        """,
        
        # Excel templates table
        """
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='excel_templates' AND xtype='U')
        CREATE TABLE excel_templates (
            template_id BIGINT IDENTITY(1,1) PRIMARY KEY,
            template_name NVARCHAR(255) NOT NULL,
            created_at DATETIME2 DEFAULT GETDATE(),
            updated_at DATETIME2 DEFAULT GETDATE(),
            user_id INT NOT NULL,
            sheet_name NVARCHAR(255),
            headers NVARCHAR(MAX),
            status NVARCHAR(20) DEFAULT 'ACTIVE',
            is_corrected BIT DEFAULT 0,
            remote_file_path NVARCHAR(512),
            validation_frequency NVARCHAR(20),
            first_identified_at DATETIME2,
            FOREIGN KEY (user_id) REFERENCES login_details(id) ON DELETE CASCADE
        )
        """,
        
        # User roles table
        """
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='user_roles' AND xtype='U')
        CREATE TABLE user_roles (
            role_id INT IDENTITY(1,1) PRIMARY KEY,
            role_name NVARCHAR(50) UNIQUE NOT NULL,
            role_description NVARCHAR(255),
            permissions NVARCHAR(MAX),
            is_active BIT DEFAULT 1,
            created_at DATETIME2 DEFAULT GETDATE()
        )
        """
    ]

def create_admin_user():
    """Create default admin user if not exists"""
    try:
        # Check if admin user exists
        check_query = "SELECT COUNT(*) FROM login_details WHERE email = ?"
        result = execute_query(check_query, ('admin@keansa.com',), fetch_one=True)
        
        if result[0] == 0:
            admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            if USE_SQLITE:
                insert_query = """
                    INSERT INTO login_details (first_name, last_name, email, mobile, password, role, is_active, is_approved)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """
            else:
                insert_query = """
                    INSERT INTO login_details (first_name, last_name, email, mobile, password, role, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
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
        logging.error(f"Failed to create admin user: {str(e)}")
        raise

def create_default_roles():
    """Create default user roles"""
    try:
        from config.settings import Config
        
        # Check if roles table has data
        check_query = "SELECT COUNT(*) FROM user_roles"
        result = execute_query(check_query, fetch_one=True)
        
        if result[0] == 0:
            default_roles = [
                ('SUPER_ADMIN', 'Super Administrator with all permissions', json.dumps(['*'])),
                ('ADMIN', 'Administrator with most permissions', json.dumps(Config.ROLE_PERMISSIONS['ADMIN'])),
                ('MANAGER', 'Manager with limited admin permissions', json.dumps(Config.ROLE_PERMISSIONS['MANAGER'])),
                ('USER', 'Regular user with basic permissions', json.dumps(Config.ROLE_PERMISSIONS['USER'])),
                ('VIEWER', 'Read-only access user', json.dumps(Config.ROLE_PERMISSIONS['VIEWER']))
            ]
            
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
        logging.error(f"Failed to create default roles: {str(e)}")
        raise

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
        raise
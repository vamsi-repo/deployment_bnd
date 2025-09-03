import sqlite3
import logging
from flask import g
from config.settings import Config

# Choose database type based on configuration
USE_SQLITE = True  # Set to False when SQL Server is ready

def get_db_connection():
    """Get database connection - SQLite for testing, SQL Server for production"""
    if USE_SQLITE:
        return get_sqlite_connection()
    else:
        return get_sqlserver_connection()

def get_sqlite_connection():
    """Get SQLite database connection for testing"""
    if 'db' not in g:
        try:
            # Create/connect to SQLite database in backend folder
            db_path = 'keansa_test.db'
            g.db = sqlite3.connect(db_path)
            g.db.row_factory = sqlite3.Row  # Return rows as dictionaries
            logging.info("SQLite database connection established successfully")
        except sqlite3.Error as err:
            logging.error(f"SQLite connection failed: {err}")
            raise Exception(f"Failed to connect to database: {str(err)}")
    
    return g.db

def get_sqlserver_connection():
    """Get SQL Server database connection"""
    import pyodbc
    if 'db' not in g:
        try:
            connection_string = (
                f"DRIVER={{{Config.DB_CONFIG['driver']}}};"
                f"SERVER={Config.DB_CONFIG['server']};"
                f"DATABASE={Config.DB_CONFIG['database']};"
                f"UID={Config.DB_CONFIG['username']};"
                f"PWD={Config.DB_CONFIG['password']};"
                f"Trusted_Connection={Config.DB_CONFIG['trusted_connection']};"
                f"Encrypt={Config.DB_CONFIG['encrypt']};"
                f"TrustServerCertificate={Config.DB_CONFIG['trust_server_certificate']};"
            )
            
            g.db = pyodbc.connect(connection_string)
            logging.info("SQL Server database connection established successfully")
            
        except pyodbc.Error as err:
            logging.error(f"SQL Server connection failed: {err}")
            raise Exception(f"Failed to connect to database: {str(err)}")
    
    return g.db

def close_db(error):
    """Close database connection"""
    db = g.pop('db', None)
    if db is not None:
        try:
            db.close()
            logging.debug("Database connection closed")
        except Exception as e:
            logging.error(f"Error closing database connection: {e}")

def execute_query(query, params=None, fetch_one=False, fetch_all=False, commit=False):
    """Execute a database query with proper error handling"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        result = None
        if fetch_one:
            result = cursor.fetchone()
        elif fetch_all:
            result = cursor.fetchall()
        
        if commit:
            conn.commit()
            
        if USE_SQLITE:
            cursor.close()
            
        return result
        
    except Exception as e:
        logging.error(f"Database query error: {e}")
        logging.error(f"Query: {query}")
        logging.error(f"Params: {params}")
        raise Exception(f"Database query failed: {str(e)}")

def get_dict_results(query, params=None):
    """Execute query and return results as list of dictionaries"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        rows = cursor.fetchall()
        
        if USE_SQLITE:
            # SQLite with row_factory already returns dict-like objects
            result = [dict(row) for row in rows]
        else:
            # For SQL Server
            columns = [column[0] for column in cursor.description] if cursor.description else []
            result = [dict(zip(columns, row)) for row in rows]
        
        cursor.close()
        return result
        
    except Exception as e:
        logging.error(f"Database dict query error: {e}")
        raise Exception(f"Database dict query failed: {str(e)}")

def check_table_exists(table_name):
    """Check if a table exists in the database"""
    try:
        if USE_SQLITE:
            query = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?"
        else:
            query = "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = ?"
        
        result = execute_query(query, (table_name,), fetch_one=True)
        return result[0] > 0 if result else False
    except Exception as e:
        logging.error(f"Error checking table existence: {e}")
        return False
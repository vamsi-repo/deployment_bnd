import sqlite3
import psycopg2
import psycopg2.extras
import logging
import os
from flask import g
from config.settings import Config

# Choose database type based on environment
USE_SQLITE = os.environ.get('DATABASE_TYPE', 'sqlite').lower() == 'sqlite'
USE_POSTGRESQL = os.environ.get('DATABASE_TYPE', 'sqlite').lower() == 'postgresql'

def get_db_connection():
    """Get database connection - SQLite for development, PostgreSQL for production"""
    if USE_POSTGRESQL and Config.DATABASE_URL:
        return get_postgresql_connection()
    elif USE_SQLITE:
        return get_sqlite_connection()
    else:
        return get_sqlite_connection()  # Fallback to SQLite

def get_postgresql_connection():
    """Get PostgreSQL database connection for Railway production"""
    if 'db' not in g:
        try:
            # Use DATABASE_URL provided by Railway
            database_url = Config.DATABASE_URL
            if database_url:
                g.db = psycopg2.connect(
                    database_url,
                    cursor_factory=psycopg2.extras.RealDictCursor
                )
                g.db.autocommit = False
                logging.info("PostgreSQL database connection established successfully")
            else:
                raise Exception("DATABASE_URL not provided")
        except Exception as err:
            logging.error(f"PostgreSQL connection failed: {err}")
            # Fallback to SQLite if PostgreSQL fails
            logging.warning("Falling back to SQLite...")
            return get_sqlite_connection()
    
    return g.db

def get_sqlite_connection():
    """Get SQLite database connection for development"""
    if 'db' not in g:
        try:
            # Create/connect to SQLite database in backend folder
            db_path = Config.DATABASE_PATH or 'keansa_test.db'
            g.db = sqlite3.connect(db_path)
            g.db.row_factory = sqlite3.Row  # Return rows as dictionaries
            logging.info("SQLite database connection established successfully")
        except sqlite3.Error as err:
            logging.error(f"SQLite connection failed: {err}")
            raise Exception(f"Failed to connect to database: {str(err)}")
    
    return g.db

def execute_query(query, params=None, fetch_one=False, fetch_all=False, commit=False):
    """Execute database query with proper error handling"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        # Execute query
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        # Handle different return types
        if fetch_one:
            result = cursor.fetchone()
            if USE_POSTGRESQL and result:
                return dict(result)
            return result
        elif fetch_all:
            results = cursor.fetchall()
            if USE_POSTGRESQL:
                return [dict(row) for row in results]
            return results
        
        # Commit if required
        if commit:
            connection.commit()
            
        return cursor.lastrowid if not (fetch_one or fetch_all) else None
        
    except Exception as e:
        logging.error(f"Database query failed: {e}")
        logging.error(f"Query: {query}")
        logging.error(f"Params: {params}")
        if 'connection' in locals():
            connection.rollback()
        raise

def get_dict_results(query, params=None):
    """Get query results as list of dictionaries"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        results = cursor.fetchall()
        
        if USE_POSTGRESQL:
            # PostgreSQL already returns dict-like objects
            return [dict(row) for row in results]
        else:
            # SQLite - convert to dict
            columns = [description[0] for description in cursor.description]
            return [dict(zip(columns, row)) for row in results]
        
    except Exception as e:
        logging.error(f"Database query failed: {e}")
        raise

def check_table_exists(table_name):
    """Check if a table exists in the database"""
    try:
        if USE_POSTGRESQL:
            query = """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = %s
                );
            """
        else:
            query = "SELECT name FROM sqlite_master WHERE type='table' AND name=?;"
        
        result = execute_query(query, (table_name,), fetch_one=True)
        
        if USE_POSTGRESQL:
            return result['exists'] if result else False
        else:
            return result is not None
            
    except Exception as e:
        logging.error(f"Error checking table existence: {e}")
        return False

def close_db(error=None):
    """Close database connection"""
    db = g.pop('db', None)
    
    if db is not None:
        try:
            db.close()
            logging.debug("Database connection closed")
        except Exception as e:
            logging.error(f"Error closing database: {e}")

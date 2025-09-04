# Temporary SQLite configuration for testing
import sqlite3
import logging
from flask import g

# For testing purposes - SQLite implementation
def get_db_connection_sqlite():
    """Get SQLite database connection for testing"""
    if 'db' not in g:
        try:
            # Create/connect to SQLite database
            g.db = sqlite3.connect('keansa_test.db')
            g.db.row_factory = sqlite3.Row  # Return rows as dictionaries
            logging.info("SQLite database connection established successfully")
        except sqlite3.Error as err:
            logging.error(f"SQLite connection failed: {err}")
            raise Exception(f"Failed to connect to database: {str(err)}")
    
    return g.db

def execute_query_sqlite(query, params=None, fetch_one=False, fetch_all=False, commit=False):
    """Execute SQLite query"""
    try:
        conn = get_db_connection_sqlite()
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
            
        return result
        
    except sqlite3.Error as e:
        logging.error(f"SQLite query error: {e}")
        logging.error(f"Query: {query}")
        raise Exception(f"Database query failed: {str(e)}")

def get_dict_results_sqlite(query, params=None):
    """Execute SQLite query and return results as list of dictionaries"""
    try:
        conn = get_db_connection_sqlite()
        cursor = conn.cursor()
        
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        rows = cursor.fetchall()
        # Convert sqlite3.Row objects to dictionaries
        result = [dict(row) for row in rows]
        
        return result
        
    except sqlite3.Error as e:
        logging.error(f"SQLite dict query error: {e}")
        raise Exception(f"Database dict query failed: {str(e)}")

def close_db_sqlite(error):
    """Close SQLite database connection"""
    db = g.pop('db', None)
    if db is not None:
        try:
            db.close()
            logging.debug("SQLite database connection closed")
        except Exception as e:
            logging.error(f"Error closing SQLite connection: {e}")
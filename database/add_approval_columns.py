import os
import sys
import logging

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

from database.connection import execute_query

def add_approval_columns():
    """Add approval columns to existing login_details table"""
    try:
        logging.info("Adding approval columns to login_details table...")
        
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
            WHERE role IN ('SUPER_ADMIN', 'ADMIN') AND is_approved = 0
        """
        execute_query(update_admin_query, commit=True)
        logging.info("Updated admin users to approved status")
        
        logging.info("Approval columns migration completed successfully")
        
    except Exception as e:
        logging.error(f"Failed to add approval columns: {str(e)}")
        raise

if __name__ == "__main__":
    add_approval_columns()

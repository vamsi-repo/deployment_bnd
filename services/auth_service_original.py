import logging
import bcrypt
from datetime import datetime
from database.connection import execute_query, get_dict_results
from config.settings import Config

class AuthService:
    """Authentication service for user management"""
    
    @staticmethod
    def authenticate_user(email, password):
        """Authenticate user login"""
        try:
            # Get user by email (allow admin login even if not approved)
            user_query = """
                SELECT id, email, first_name, last_name, password, role, is_active, is_approved 
                FROM login_details 
                WHERE LOWER(email) = LOWER(?) AND is_active = 1 AND 
                (is_approved = 1 OR role IN ('SUPER_ADMIN', 'ADMIN'))
            """
            users = get_dict_results(user_query, (email.lower(),))
            
            if not users:
                return {'success': False, 'message': 'Invalid credentials'}
            
            user = users[0]
            
            # Check password
            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                return {
                    'success': True, 
                    'user': {
                        'id': user['id'],
                        'email': user['email'],
                        'first_name': user['first_name'],
                        'last_name': user['last_name'],
                        'role': user['role']
                    }
                }
            else:
                return {'success': False, 'message': 'Invalid credentials'}
                
        except Exception as e:
            logging.error(f"Authentication error: {str(e)}")
            return {'success': False, 'message': f'Authentication error: {str(e)}'}
    
    @staticmethod
    def register_user(user_data):
        """Register a new user"""
        try:
            # Check if email already exists
            check_query = "SELECT COUNT(*) FROM login_details WHERE LOWER(email) = LOWER(?)"
            result = execute_query(check_query, (user_data['email'].lower(),), fetch_one=True)
            
            if result[0] > 0:
                return {'success': False, 'message': 'Email already exists'}
            
            # Hash password
            hashed_password = bcrypt.hashpw(user_data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Insert user
            insert_query = """
                INSERT INTO login_details (first_name, last_name, email, mobile, password, role)
                VALUES (?, ?, ?, ?, ?, ?)
            """
            
            execute_query(
                insert_query,
                (
                    user_data['first_name'],
                    user_data['last_name'],
                    user_data['email'],
                    user_data['mobile'],
                    hashed_password,
                    user_data.get('role', 'USER')
                ),
                commit=True
            )
            
            # Get the created user
            users = get_dict_results(
                "SELECT id, email, first_name, last_name, role FROM login_details WHERE email = ?",
                (user_data['email'],)
            )
            
            if users:
                return {
                    'success': True,
                    'message': 'Registration successful',
                    'user': users[0]
                }
            else:
                return {'success': False, 'message': 'Failed to create user'}
                
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            return {'success': False, 'message': f'Registration error: {str(e)}'}
    
    @staticmethod
    def reset_password(email, new_password):
        """Reset user password"""
        try:
            # Check if user exists
            check_query = "SELECT COUNT(*) FROM login_details WHERE email = ?"
            result = execute_query(check_query, (email,), fetch_one=True)
            
            if result[0] == 0:
                return {'success': False, 'message': 'Email not found'}
            
            # Hash new password
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Update password - SQLite compatible
            update_query = "UPDATE login_details SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?"
            execute_query(update_query, (hashed_password, email), commit=True)
            
            return {'success': True, 'message': 'Password reset successful'}
            
        except Exception as e:
            logging.error(f"Password reset error: {str(e)}")
            return {'success': False, 'message': f'Error resetting password: {str(e)}'}
    
    @staticmethod
    def update_last_login(user_id):
        """Update user's last login timestamp"""
        try:
            update_query = "UPDATE login_details SET last_login = CURRENT_TIMESTAMP WHERE id = ?"
            execute_query(update_query, (user_id,), commit=True)
        except Exception as e:
            logging.error(f"Error updating last login: {e}")
    
    @staticmethod
    def get_all_users():
        """Get all users"""
        try:
            query = """
                SELECT id, first_name, last_name, email, mobile, role, is_active, is_approved,
                       created_at, last_login, approved_at
                FROM login_details 
                ORDER BY created_at DESC
            """
            return get_dict_results(query)
        except Exception as e:
            logging.error(f"Error fetching users: {str(e)}")
            raise
    
    @staticmethod
    def get_pending_users():
        """Get users pending approval"""
        try:
            query = """
                SELECT id, first_name, last_name, email, mobile, role, is_active, is_approved,
                       created_at
                FROM login_details 
                WHERE is_approved = 0
                ORDER BY created_at DESC
            """
            return get_dict_results(query)
        except Exception as e:
            logging.error(f"Error fetching pending users: {str(e)}")
            raise
    
    @staticmethod
    def approve_user(user_id, approved_by_id):
        """Approve a user"""
        try:
            update_query = """
                UPDATE login_details 
                SET is_approved = 1, approved_by = ?, approved_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """
            execute_query(update_query, (approved_by_id, user_id), commit=True)
            return {'success': True, 'message': 'User approved successfully'}
        except Exception as e:
            logging.error(f"Error approving user: {str(e)}")
            return {'success': False, 'message': f'Error approving user: {str(e)}'}
    
    @staticmethod
    def update_user_role(user_id, new_role, updated_by_role):
        """Update user role"""
        try:
            # Check if current user can assign this role
            if not AuthService.can_assign_role(updated_by_role, new_role):
                return {'success': False, 'message': 'Cannot assign this role'}
            
            update_query = "UPDATE login_details SET role = ? WHERE id = ?"
            execute_query(update_query, (new_role, user_id), commit=True)
            return {'success': True, 'message': 'User role updated successfully'}
        except Exception as e:
            logging.error(f"Error updating user role: {str(e)}")
            return {'success': False, 'message': f'Error updating user role: {str(e)}'}
    
    @staticmethod
    def deactivate_user(user_id):
        """Deactivate a user"""
        try:
            update_query = "UPDATE login_details SET is_active = 0 WHERE id = ?"
            execute_query(update_query, (user_id,), commit=True)
            return {'success': True, 'message': 'User deactivated successfully'}
        except Exception as e:
            logging.error(f"Error deactivating user: {str(e)}")
            return {'success': False, 'message': f'Error deactivating user: {str(e)}'}
    
    @staticmethod
    def activate_user(user_id):
        """Activate a user"""
        try:
            update_query = "UPDATE login_details SET is_active = 1 WHERE id = ?"
            execute_query(update_query, (user_id,), commit=True)
            return {'success': True, 'message': 'User activated successfully'}
        except Exception as e:
            logging.error(f"Error activating user: {str(e)}")
            return {'success': False, 'message': f'Error activating user: {str(e)}'}
    
    @staticmethod
    def get_user_by_id(user_id):
        """Get user by ID"""
        try:
            query = """
                SELECT id, first_name, last_name, email, mobile, role, is_active, 
                       created_at, last_login 
                FROM login_details 
                WHERE id = ?
            """
            users = get_dict_results(query, (user_id,))
            return users[0] if users else None
        except Exception as e:
            logging.error(f"Error fetching user: {str(e)}")
            raise
    
    @staticmethod
    def can_assign_role(current_user_role, target_role):
        """Check if current user can assign target role"""
        current_hierarchy = Config.USER_ROLES.get(current_user_role, 999)
        target_hierarchy = Config.USER_ROLES.get(target_role, 999)
        
        # Can only assign roles with equal or lower privilege (higher number)
        return current_hierarchy <= target_hierarchy
    
    @staticmethod
    def can_manage_user(current_user_role, target_user_role):
        """Check if current user can manage target user"""
        current_hierarchy = Config.USER_ROLES.get(current_user_role, 999)
        target_hierarchy = Config.USER_ROLES.get(target_user_role, 999)
        
        # Can only manage users with lower privilege (higher number)
        return current_hierarchy < target_hierarchy
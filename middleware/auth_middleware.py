import logging
from functools import wraps
from flask import session, request, jsonify, g
from database.connection import get_dict_results
from config.settings import Config

def setup_auth_middleware(app):
    """Setup authentication middleware"""
    
    @app.before_request
    def load_logged_in_user():
        """Load user information before each request"""
        g.user = None
        g.user_role = None
        g.user_permissions = []
        g.user_approved = False
        
        if 'loggedin' in session and 'user_id' in session:
            try:
                user_query = """
                    SELECT id, email, first_name, last_name, role, is_active, is_approved
                    FROM login_details 
                    WHERE id = ? AND is_active = 1
                """
                users = get_dict_results(user_query, (session['user_id'],))
                
                if users:
                    user = users[0]
                    g.user = user
                    g.user_role = user['role']
                    g.user_approved = bool(user['is_approved']) or user['role'] in ['SUPER_ADMIN', 'ADMIN']
                    
                    # Get user permissions based on role (only if approved or admin)
                    if g.user_approved and user['role'] in Config.ROLE_PERMISSIONS:
                        g.user_permissions = Config.ROLE_PERMISSIONS[user['role']]
                    elif g.user_approved:
                        g.user_permissions = Config.ROLE_PERMISSIONS['USER']  # Default
                    else:
                        g.user_permissions = []  # No permissions for unapproved users
                        
                    logging.debug(f"User loaded: {user['email']}, Role: {user['role']}, Approved: {g.user_approved}")
                else:
                    # User not found or inactive, clear session
                    session.clear()
                    logging.warning("User not found or inactive, session cleared")
            except Exception as e:
                logging.error(f"Error loading user: {e}")
                session.clear()

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or 'user_id' not in session or g.user is None:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def role_required(*allowed_roles):
    """Decorator to require specific role(s) for protected routes"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'loggedin' not in session or 'user_id' not in session or g.user is None:
                return jsonify({'success': False, 'message': 'Authentication required'}), 401
            
            if g.user_role not in allowed_roles:
                return jsonify({'success': False, 'message': 'Insufficient permissions'}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def permission_required(*required_permissions):
    """Decorator to require specific permission(s) for protected routes"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'loggedin' not in session or 'user_id' not in session or g.user is None:
                return jsonify({'success': False, 'message': 'Authentication required'}), 401
            
            # Super admin has all permissions
            if '*' in g.user_permissions:
                return f(*args, **kwargs)
            
            # Check if user has any of the required permissions
            has_permission = any(perm in g.user_permissions for perm in required_permissions)
            
            if not has_permission:
                return jsonify({'success': False, 'message': 'Insufficient permissions'}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def approval_required(f):
    """Decorator to require user approval for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or 'user_id' not in session or g.user is None:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        if not g.user_approved:
            return jsonify({
                'success': False, 
                'message': 'Account pending admin approval',
                'requires_approval': True
            }), 403
            
        return f(*args, **kwargs)
    return decorated_function

def get_user_role_hierarchy():
    """Get user role hierarchy value (lower number = higher privilege)"""
    if g.user_role in Config.USER_ROLES:
        return Config.USER_ROLES[g.user_role]
    return 999  # Unknown role, lowest privilege

def can_manage_user(target_user_role):
    """Check if current user can manage target user based on role hierarchy"""
    current_hierarchy = get_user_role_hierarchy()
    target_hierarchy = Config.USER_ROLES.get(target_user_role, 999)
    
    # Can only manage users with equal or lower privilege (higher number)
    return current_hierarchy < target_hierarchy
import logging
import bcrypt
from flask import Blueprint, request, jsonify, session, g
from middleware.auth_middleware import login_required, role_required, permission_required
from services.auth_service import AuthService

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/check-auth', methods=['GET'])
def check_auth():
    """Check if user is authenticated and return user info"""
    try:
        logging.debug(f"Checking auth with session: {dict(session)}")
        
        if 'loggedin' in session and 'user_id' in session and g.user:
            user_data = {
                'email': g.user['email'],
                'id': g.user['id'],
                'first_name': g.user['first_name'],
                'last_name': g.user['last_name'],
                'role': g.user['role'],
                'permissions': g.user_permissions,
                'is_approved': g.user_approved
            }
            
            logging.info(f"User {g.user['email']} is authenticated with role {g.user['role']}, approved: {g.user_approved}")
            return jsonify({
                'success': True,
                'user': user_data,
                'is_approved': g.user_approved,
                'message': 'Account pending admin approval' if not g.user_approved else 'Authenticated'
            })
        
        logging.warning("User not authenticated")
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
        
    except Exception as e:
        logging.error(f"Error in check-auth endpoint: {str(e)}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@auth_bp.route('/authenticate', methods=['POST'])
def authenticate():
    """Authenticate user login"""
    try:
        # Handle both form data and JSON
        if request.is_json:
            data = request.get_json()
            email = data.get('email') or data.get('username')
            password = data.get('password')
        else:
            email = request.form.get('username') or request.form.get('email')
            password = request.form.get('password')
        
        logging.debug(f"Login attempt: email={email}")
        
        if not email or not password:
            logging.warning("Login failed: Email or password missing")
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400

        # Special admin login for backward compatibility
        if email == "admin" and password == "admin":
            session['loggedin'] = True
            session['user_email'] = "admin@keansa.com"
            session['user_id'] = 1
            session.permanent = True
            logging.info("Admin login successful")
            return jsonify({
                'success': True, 
                'message': 'Login successful', 
                'user': {
                    'email': 'admin@keansa.com', 
                    'id': 1,
                    'role': 'SUPER_ADMIN',
                    'first_name': 'Admin'
                }
            }), 200

        # Regular authentication
        auth_result = AuthService.authenticate_user(email, password)
        
        if auth_result['success']:
            user = auth_result['user']
            session['loggedin'] = True
            session['user_email'] = user['email']
            session['user_id'] = user['id']
            session.permanent = True
            
            # Update last login
            AuthService.update_last_login(user['id'])
            
            logging.info(f"User {email} logged in successfully")
            
            # Return response with approval status
            response_data = {
                'success': True,
                'message': auth_result.get('message', 'Login successful'),
                'user': {
                    'email': user['email'], 
                    'id': user['id'],
                    'role': user['role'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'is_approved': user.get('is_approved', 1)
                },
                'is_approved': auth_result.get('is_approved', 1)
            }
            
            return jsonify(response_data), 200
        else:
            logging.warning(f"Authentication failed for {email}: {auth_result['message']}")
            return jsonify({'success': False, 'message': auth_result['message']}), 401
            
    except Exception as e:
        logging.error(f"Unexpected error during login: {str(e)}")
        return jsonify({'success': False, 'message': f'Unexpected error: {str(e)}'}), 500

@auth_bp.route('/admin/register', methods=['POST'])
@permission_required('user.create')
def admin_register():
    """Admin-controlled user registration (requires user.create permission)"""
    try:
        # Handle both form data and JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        mobile = data.get('mobile')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        user_role = data.get('role', 'USER')  # Allow role assignment for admin

        if not all([first_name, last_name, email, mobile, password, confirm_password]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
            
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400

        # Validate role assignment permissions
        if not AuthService.can_assign_role(g.user_role, user_role):
            return jsonify({'success': False, 'message': 'Cannot assign this role'}), 403

        registration_result = AuthService.register_user({
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'mobile': mobile,
            'password': password,
            'role': user_role
        })
        
        if registration_result['success']:
            return jsonify({
                'success': True,
                'message': 'User registered successfully',
                'user': registration_result['user']
            }), 200
        else:
            return jsonify({'success': False, 'message': registration_result['message']}), 400
            
    except Exception as e:
        logging.error(f"Admin registration error: {str(e)}")
        return jsonify({'success': False, 'message': f'Registration error: {str(e)}'}), 500

@auth_bp.route('/register', methods=['POST'])
def register():
    """Public user registration endpoint"""
    try:
        # Handle both form data and JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        mobile = data.get('mobile')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        # Default role for public registration
        user_role = 'USER'

        if not all([first_name, last_name, email, mobile, password, confirm_password]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
            
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400

        registration_result = AuthService.register_user({
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'mobile': mobile,
            'password': password,
            'role': user_role
        })
        
        if registration_result['success']:
            return jsonify({
                'success': True,
                'message': 'Registration successful',
                'user': registration_result['user']
            }), 200
        else:
            return jsonify({'success': False, 'message': registration_result['message']}), 400
            
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'message': f'Registration error: {str(e)}'}), 500

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset user password"""
    try:
        data = request.get_json() or request.form.to_dict()
        email = data.get('email')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not all([email, new_password, confirm_password]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
            
        if new_password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400

        reset_result = AuthService.reset_password(email, new_password)
        
        if reset_result['success']:
            return jsonify({'success': True, 'message': 'Password reset successful'}), 200
        else:
            return jsonify({'success': False, 'message': reset_result['message']}), 404
            
    except Exception as e:
        logging.error(f"Password reset error: {str(e)}")
        return jsonify({'success': False, 'message': f'Error resetting password: {str(e)}'}), 500

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logout user and clear session"""
    try:
        user_email = session.get('user_email', 'unknown')
        logging.info(f"User {user_email} logged out")
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    except Exception as e:
        logging.error(f"Logout error: {str(e)}")
        return jsonify({'success': False, 'message': f'Logout error: {str(e)}'}), 500

@auth_bp.route('/users', methods=['GET'])
@permission_required('user.read')
def get_users():
    """Get list of users (requires user.read permission)"""
    try:
        users = AuthService.get_all_users()
        return jsonify({'success': True, 'users': users})
    except Exception as e:
        logging.error(f"Error fetching users: {str(e)}")
        return jsonify({'success': False, 'message': f'Error fetching users: {str(e)}'}), 500

@auth_bp.route('/users/pending', methods=['GET'])
@permission_required('user.read')
def get_pending_users():
    """Get users pending approval"""
    try:
        users = AuthService.get_pending_users()
        return jsonify({'success': True, 'users': users})
    except Exception as e:
        logging.error(f"Error fetching pending users: {str(e)}")
        return jsonify({'success': False, 'message': f'Error fetching pending users: {str(e)}'}), 500

@auth_bp.route('/users/<int:user_id>/approve', methods=['POST'])
@permission_required('user.update')
def approve_user(user_id):
    """Approve a user"""
    try:
        result = AuthService.approve_user(user_id, g.user['id'])
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
    except Exception as e:
        logging.error(f"Error approving user: {str(e)}")
        return jsonify({'success': False, 'message': f'Error approving user: {str(e)}'}), 500

@auth_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@permission_required('user.update')
def update_user_role(user_id):
    """Update user role"""
    try:
        data = request.get_json()
        new_role = data.get('role')
        
        if not new_role:
            return jsonify({'success': False, 'message': 'Role is required'}), 400
        
        result = AuthService.update_user_role(user_id, new_role, g.user_role)
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
    except Exception as e:
        logging.error(f"Error updating user role: {str(e)}")
        return jsonify({'success': False, 'message': f'Error updating user role: {str(e)}'}), 500

@auth_bp.route('/users/<int:user_id>/activate', methods=['POST'])
@permission_required('user.update')
def activate_user_endpoint(user_id):
    """Activate a user"""
    try:
        result = AuthService.activate_user(user_id)
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
    except Exception as e:
        logging.error(f"Error activating user: {str(e)}")
        return jsonify({'success': False, 'message': f'Error activating user: {str(e)}'}), 500

@auth_bp.route('/users/<int:user_id>/deactivate', methods=['POST'])
@permission_required('user.update')
def deactivate_user_endpoint(user_id):
    """Deactivate a user"""
    try:
        result = AuthService.deactivate_user(user_id)
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
    except Exception as e:
        logging.error(f"Error deactivating user: {str(e)}")
        return jsonify({'success': False, 'message': f'Error deactivating user: {str(e)}'}), 500

@auth_bp.route('/users/<int:user_id>', methods=['PUT'])
@permission_required('user.update')
def update_user(user_id):
    """Update user information"""
    try:
        data = request.get_json()
        
        # Check if current user can manage the target user
        target_user = AuthService.get_user_by_id(user_id)
        if not target_user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        if not AuthService.can_manage_user(g.user_role, target_user['role']):
            return jsonify({'success': False, 'message': 'Cannot manage this user'}), 403

        update_result = AuthService.update_user(user_id, data)
        
        if update_result['success']:
            return jsonify({'success': True, 'message': 'User updated successfully'})
        else:
            return jsonify({'success': False, 'message': update_result['message']}), 400
            
    except Exception as e:
        logging.error(f"Error updating user: {str(e)}")
        return jsonify({'success': False, 'message': f'Error updating user: {str(e)}'}), 500

@auth_bp.route('/users/<int:user_id>', methods=['DELETE'])
@permission_required('user.delete')
def delete_user(user_id):
    """Delete user (requires user.delete permission)"""
    try:
        # Check if current user can manage the target user
        target_user = AuthService.get_user_by_id(user_id)
        if not target_user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        if not AuthService.can_manage_user(g.user_role, target_user['role']):
            return jsonify({'success': False, 'message': 'Cannot delete this user'}), 403
            
        # Prevent deleting self
        if user_id == g.user['id']:
            return jsonify({'success': False, 'message': 'Cannot delete your own account'}), 400

        delete_result = AuthService.delete_user(user_id)
        
        if delete_result['success']:
            return jsonify({'success': True, 'message': 'User deleted successfully'})
        else:
            return jsonify({'success': False, 'message': delete_result['message']}), 400
            
    except Exception as e:
        logging.error(f"Error deleting user: {str(e)}")
        return jsonify({'success': False, 'message': f'Error deleting user: {str(e)}'}), 500

@auth_bp.route('/roles', methods=['GET'])
@permission_required('role.manage')
def get_roles():
    """Get available roles"""
    try:
        from config.settings import Config
        roles = list(Config.USER_ROLES.keys())
        # Filter roles based on current user's ability to assign them
        available_roles = []
        for role in roles:
            if AuthService.can_assign_role(g.user_role, role):
                available_roles.append({
                    'name': role,
                    'hierarchy': Config.USER_ROLES[role],
                    'permissions': Config.ROLE_PERMISSIONS.get(role, [])
                })
        return jsonify({'success': True, 'roles': available_roles})
    except Exception as e:
        logging.error(f"Error fetching roles: {str(e)}")
        return jsonify({'success': False, 'message': f'Error fetching roles: {str(e)}'}), 500
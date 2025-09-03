"""
Database queries module for common SQL operations
"""

# User queries
GET_USER_BY_EMAIL = """
    SELECT id, first_name, last_name, email, password, role, is_active, last_login
    FROM login_details 
    WHERE LOWER(email) = LOWER(?) AND is_active = 1
"""

GET_USER_BY_ID = """
    SELECT id, first_name, last_name, email, role, is_active, created_at, last_login
    FROM login_details 
    WHERE id = ?
"""

CREATE_USER = """
    INSERT INTO login_details (first_name, last_name, email, mobile, password, role, is_active, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, GETDATE())
"""

UPDATE_USER_LAST_LOGIN = """
    UPDATE login_details 
    SET last_login = GETDATE() 
    WHERE id = ?
"""

# Role queries
GET_ALL_ROLES = """
    SELECT role_name, role_description, permissions 
    FROM user_roles 
    WHERE is_active = 1
"""

# Template queries (basic for now)
GET_USER_TEMPLATES = """
    SELECT template_id, template_name, created_at, status
    FROM excel_templates
    WHERE user_id = ? AND status = 'ACTIVE'
    ORDER BY created_at DESC
"""
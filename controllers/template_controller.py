from flask import Blueprint, jsonify, session, g
from middleware.auth_middleware import login_required, permission_required
import logging

template_bp = Blueprint('template', __name__)

@template_bp.route('/templates', methods=['GET'])
@login_required
@permission_required('template.read')
def get_templates():
    """Get user templates"""
    try:
        # Basic implementation - you can expand this
        return jsonify({
            'success': True,
            'templates': [],
            'message': 'Templates endpoint working'
        })
    except Exception as e:
        logging.error(f'Error fetching templates: {str(e)}')
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
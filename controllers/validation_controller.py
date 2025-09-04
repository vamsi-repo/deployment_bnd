from flask import Blueprint, jsonify, session, g
from middleware.auth_middleware import login_required, permission_required
import logging

validation_bp = Blueprint('validation', __name__)

@validation_bp.route('/validate', methods=['GET'])
@login_required
@permission_required('validation.read')
def validate():
    """Basic validation endpoint"""
    try:
        return jsonify({
            'success': True,
            'message': 'Validation endpoint working'
        })
    except Exception as e:
        logging.error(f'Error in validation: {str(e)}')
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
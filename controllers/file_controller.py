from flask import Blueprint, jsonify, session, g
from middleware.auth_middleware import login_required, permission_required
import logging

file_bp = Blueprint('file', __name__)

@file_bp.route('/upload', methods=['POST'])
@login_required
@permission_required('file.upload')
def upload_file():
    """Basic file upload endpoint"""
    try:
        return jsonify({
            'success': True,
            'message': 'File upload endpoint working'
        })
    except Exception as e:
        logging.error(f'Error in file upload: {str(e)}')
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
#!/usr/bin/env python3
"""
WSGI entry point for Railway deployment
"""
import os
import logging
from app import create_app, initialize_database

# Create the application instance
app = create_app()

# Initialize database on startup (only once)
if __name__ != '__main__':
    # This runs when gunicorn imports this module
    try:
        with app.app_context():
            initialize_database()
        logging.info("Database initialized successfully for production")
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")
        # Don't fail the entire app if database init fails
        pass

if __name__ == '__main__':
    # This runs for local development
    with app.app_context():
        initialize_database()
    
    port = int(os.environ.get('PORT', 5000))
    logging.info(f"Starting Flask server on port {port}")
    app.run(
        debug=app.config['DEBUG'],
        host='0.0.0.0',
        port=port
    )
#!/usr/bin/env python3
"""
Railway Deployment Health Check Script
Run this to diagnose deployment issues
"""

import os
import sys
import logging

def check_environment():
    """Check if all required environment variables are set"""
    print("🔍 Checking environment variables...")
    
    required_vars = [
        'PORT',
        'SECRET_KEY',
        'ENVIRONMENT'
    ]
    
    optional_vars = [
        'DATABASE_URL',
        'DATABASE_TYPE',
        'CORS_ORIGINS'
    ]
    
    for var in required_vars:
        value = os.environ.get(var)
        if value:
            print(f"✅ {var} = {value}")
        else:
            print(f"❌ {var} = NOT SET (required)")
    
    for var in optional_vars:
        value = os.environ.get(var)
        print(f"📋 {var} = {value or 'NOT SET'}")

def check_imports():
    """Check if all imports work correctly"""
    print("\n🔍 Checking imports...")
    
    try:
        import flask
        print(f"✅ Flask {flask.__version__}")
    except ImportError as e:
        print(f"❌ Flask import failed: {e}")
        return False
    
    try:
        import bcrypt
        print("✅ bcrypt")
    except ImportError as e:
        print(f"❌ bcrypt import failed: {e}")
        return False
    
    try:
        import psycopg2
        print(f"✅ psycopg2")
    except ImportError as e:
        print(f"❌ psycopg2 import failed: {e}")
        return False
    
    try:
        from app import create_app
        print("✅ app.create_app")
    except ImportError as e:
        print(f"❌ app import failed: {e}")
        return False
    
    return True

def test_app_creation():
    """Test if the Flask app can be created"""
    print("\n🔍 Testing app creation...")
    
    try:
        from app import create_app
        app = create_app()
        print("✅ Flask app created successfully")
        return True
    except Exception as e:
        print(f"❌ App creation failed: {e}")
        return False

def main():
    """Run all health checks"""
    print("🏥 Railway Deployment Health Check")
    print("=" * 40)
    
    check_environment()
    
    if not check_imports():
        print("\n❌ Import checks failed. Deployment will fail.")
        sys.exit(1)
    
    if not test_app_creation():
        print("\n❌ App creation failed. Deployment will fail.")
        sys.exit(1)
    
    print("\n✅ All checks passed! Deployment should succeed.")
    print("\n🚀 Ready for Railway deployment!")

if __name__ == '__main__':
    main()

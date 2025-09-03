#!/bin/bash

# Railway Backend Deployment Script for Keansa Data Validation

echo "🚀 Deploying Keansa Backend to Railway..."

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "❌ Railway CLI not found. Please install it first:"
    echo "npm install -g @railway/cli"
    exit 1
fi

# Check if logged in to Railway
if ! railway whoami &> /dev/null; then
    echo "🔑 Please login to Railway first:"
    railway login
fi

echo "📁 Setting up backend deployment..."

# Navigate to backend directory
cd "$(dirname "$0")"

# Create .railwayignore file
cat > .railwayignore << EOF
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
env/
venv/
.venv/
.env
.env.local
.env.development
.git/
.gitignore
*.log
sessions/
uploads/
keansa_test.db
.DS_Store
Thumbs.db
EOF

echo "🔧 Backend deployment files created:"
echo "✅ Procfile"
echo "✅ runtime.txt"
echo "✅ requirements.txt"
echo "✅ railway.toml"
echo "✅ .env.production"
echo "✅ .railwayignore"

echo ""
echo "📋 Next steps:"
echo "1. Create a new Railway project: railway new"
echo "2. Add PostgreSQL database: railway add postgresql"
echo "3. Set environment variables in Railway dashboard"
echo "4. Deploy: railway up"
echo "5. Run migration: curl -X POST https://your-domain.railway.app/api/migrate"

echo ""
echo "🔗 Environment variables to set in Railway:"
echo "- SECRET_KEY=your-super-secret-key"
echo "- DEBUG=false"
echo "- ENVIRONMENT=production"
echo "- DATABASE_TYPE=postgresql"
echo "- CORS_ORIGINS=https://your-frontend-domain.railway.app"

echo ""
echo "✨ Ready for Railway deployment!"

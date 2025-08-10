#!/bin/bash

# AI Threat Intelligence & Incident Response Platform Setup Script
# This script sets up the development environment for the platform

set -e

echo "🚀 Setting up AI Threat Intelligence & Incident Response Platform..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_success "Docker and Docker Compose are installed"
}

# Check if Node.js is installed
check_node() {
    if ! command -v node &> /dev/null; then
        print_warning "Node.js is not installed. Installing via Docker instead."
        return 1
    fi
    
    NODE_VERSION=$(node --version)
    print_success "Node.js $NODE_VERSION is installed"
    return 0
}

# Check if Python is installed
check_python() {
    if ! command -v python3 &> /dev/null; then
        print_warning "Python 3 is not installed. Installing via Docker instead."
        return 1
    fi
    
    PYTHON_VERSION=$(python3 --version)
    print_success "$PYTHON_VERSION is installed"
    return 0
}

# Create environment files
create_env_files() {
    print_status "Creating environment files..."
    
    # Backend .env file
    if [ ! -f backend/.env ]; then
        cat > backend/.env << EOF
# Database
DATABASE_URL=postgresql://threat_user:threat_password@localhost/threat_intel

# Redis
REDIS_URL=redis://localhost:6379

# Security
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -hex 32)
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Application
DEBUG=true
LOG_LEVEL=INFO

# External APIs (add your keys here)
CVE_API_KEY=
THREAT_FEED_API_KEY=
VIRUSTOTAL_API_KEY=
ALIENVAULT_API_KEY=

# AI/ML Configuration
MODEL_PATH=./ml/models/
ML_ENABLED=true

# File Upload
MAX_FILE_SIZE=10485760
UPLOAD_DIR=./uploads/

# Email (configure for notifications)
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_TLS=true

# Cloud Storage (configure for production)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-east-1
S3_BUCKET=
EOF
        print_success "Created backend/.env file"
    else
        print_warning "backend/.env already exists"
    fi
    
    # Frontend .env file
    if [ ! -f frontend/.env ]; then
        cat > frontend/.env << EOF
REACT_APP_API_URL=http://localhost:8000
REACT_APP_VERSION=1.0.0
REACT_APP_NAME="AI Threat Intelligence Platform"
EOF
        print_success "Created frontend/.env file"
    else
        print_warning "frontend/.env already exists"
    fi
}

# Setup Python virtual environment
setup_python_env() {
    if check_python; then
        print_status "Setting up Python virtual environment..."
        cd backend
        
        if [ ! -d "venv" ]; then
            python3 -m venv venv
            print_success "Created Python virtual environment"
        fi
        
        source venv/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt
        print_success "Installed Python dependencies"
        
        cd ..
    fi
}

# Setup Node.js dependencies
setup_node_env() {
    if check_node; then
        print_status "Setting up Node.js dependencies..."
        cd frontend
        
        if [ ! -d "node_modules" ]; then
            npm install
            print_success "Installed Node.js dependencies"
        else
            print_warning "node_modules already exists"
        fi
        
        cd ..
    fi
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p backend/uploads
    mkdir -p backend/logs
    mkdir -p backend/ml/models
    mkdir -p frontend/public
    mkdir -p docs
    mkdir -p scripts
    
    print_success "Created necessary directories"
}

# Initialize database
init_database() {
    print_status "Initializing database..."
    
    # Create database initialization script
    cat > backend/init.sql << EOF
-- Create database if it doesn't exist
SELECT 'CREATE DATABASE threat_intel'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'threat_intel')\gexec

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE threat_intel TO threat_user;
EOF
    
    print_success "Created database initialization script"
}

# Create development scripts
create_dev_scripts() {
    print_status "Creating development scripts..."
    
    # Backend development script
    cat > scripts/dev-backend.sh << 'EOF'
#!/bin/bash
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
EOF
    chmod +x scripts/dev-backend.sh
    
    # Frontend development script
    cat > scripts/dev-frontend.sh << 'EOF'
#!/bin/bash
cd frontend
npm start
EOF
    chmod +x scripts/dev-frontend.sh
    
    # Full development script
    cat > scripts/dev.sh << 'EOF'
#!/bin/bash
# Start all services in development mode
echo "Starting development environment..."
echo "Backend: http://localhost:8000"
echo "Frontend: http://localhost:3000"
echo "API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all services"

# Start backend
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Start frontend
cd ../frontend
npm start &
FRONTEND_PID=$!

# Wait for interrupt
trap "echo 'Stopping services...'; kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait
EOF
    chmod +x scripts/dev.sh
    
    print_success "Created development scripts"
}

# Create production deployment script
create_prod_script() {
    print_status "Creating production deployment script..."
    
    cat > scripts/deploy.sh << 'EOF'
#!/bin/bash
# Production deployment script

echo "🚀 Deploying AI Threat Intelligence Platform..."

# Build and start services
docker-compose -f docker-compose.yml --profile production up -d --build

echo "✅ Deployment complete!"
echo "🌐 Frontend: http://localhost"
echo "🔧 Backend API: http://localhost/api"
echo "📚 API Documentation: http://localhost/api/docs"
EOF
    chmod +x scripts/deploy.sh
    
    print_success "Created production deployment script"
}

# Main setup function
main() {
    print_status "Starting setup process..."
    
    # Check prerequisites
    check_docker
    
    # Create environment files
    create_env_files
    
    # Create directories
    create_directories
    
    # Setup Python environment
    setup_python_env
    
    # Setup Node.js environment
    setup_node_env
    
    # Initialize database
    init_database
    
    # Create development scripts
    create_dev_scripts
    
    # Create production script
    create_prod_script
    
    print_success "Setup completed successfully!"
    echo ""
    echo "🎯 Next steps:"
    echo "1. Configure your API keys in backend/.env"
    echo "2. Start development environment: ./scripts/dev.sh"
    echo "3. Or use Docker: docker-compose up -d"
    echo "4. Access the application:"
    echo "   - Frontend: http://localhost:3000"
    echo "   - Backend API: http://localhost:8000"
    echo "   - API Docs: http://localhost:8000/docs"
    echo ""
    echo "📚 For more information, see the README.md file"
}

# Run main function
main "$@" 
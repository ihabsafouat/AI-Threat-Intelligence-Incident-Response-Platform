#!/bin/bash
# CDK Deployment Script for Threat Intelligence Platform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT=${ENVIRONMENT:-"dev"}
REGION=${AWS_REGION:-"us-east-1"}
ACCOUNT=${AWS_ACCOUNT_ID:-""}

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

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if CDK is installed
    if ! command -v cdk &> /dev/null; then
        print_error "AWS CDK is not installed. Please install it first: npm install -g aws-cdk"
        exit 1
    fi
    
    # Check if Python is available
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Please install it first."
        exit 1
    fi
    
    # Check if pip is available
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 is not installed. Please install it first."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Function to setup Python environment
setup_python_env() {
    print_status "Setting up Python environment..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        print_status "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install dependencies
    print_status "Installing Python dependencies..."
    pip3 install -r requirements.txt
    
    print_success "Python environment setup completed"
}

# Function to bootstrap CDK
bootstrap_cdk() {
    print_status "Bootstrapping CDK for region $REGION..."
    
    if [ -n "$ACCOUNT" ]; then
        cdk bootstrap aws://$ACCOUNT/$REGION
    else
        cdk bootstrap
    fi
    
    print_success "CDK bootstrap completed"
}

# Function to deploy infrastructure
deploy_infrastructure() {
    print_status "Deploying infrastructure for environment: $ENVIRONMENT"
    
    # Set environment variables
    export ENVIRONMENT=$ENVIRONMENT
    export AWS_REGION=$REGION
    
    # Deploy the stack
    cdk deploy --require-approval never
    
    print_success "Infrastructure deployment completed"
}

# Function to destroy infrastructure
destroy_infrastructure() {
    print_warning "This will destroy all infrastructure resources!"
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Destroying infrastructure..."
        cdk destroy --force
        print_success "Infrastructure destruction completed"
    else
        print_status "Infrastructure destruction cancelled"
    fi
}

# Function to show stack status
show_status() {
    print_status "Showing stack status..."
    cdk list
    cdk diff
}

# Function to show help
show_help() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  deploy     Deploy the infrastructure"
    echo "  destroy    Destroy the infrastructure"
    echo "  status     Show stack status and differences"
    echo "  bootstrap  Bootstrap CDK for the account/region"
    echo "  setup      Setup Python environment and dependencies"
    echo "  help       Show this help message"
    echo ""
    echo "Options:"
    echo "  -e, --environment ENV    Environment name (default: dev)"
    echo "  -r, --region REGION      AWS region (default: us-east-1)"
    echo "  -a, --account ACCOUNT   AWS account ID"
    echo ""
    echo "Environment Variables:"
    echo "  ENVIRONMENT     Environment name"
    echo "  AWS_REGION      AWS region"
    echo "  AWS_ACCOUNT_ID  AWS account ID"
    echo ""
    echo "Examples:"
    echo "  $0 deploy -e prod -r us-west-2"
    echo "  $0 setup"
    echo "  $0 status"
}

# Parse command line arguments
COMMAND=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        -a|--account)
            ACCOUNT="$2"
            shift 2
            ;;
        deploy|destroy|status|bootstrap|setup|help)
            COMMAND="$1"
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# If no command specified, show help
if [ -z "$COMMAND" ]; then
    show_help
    exit 1
fi

# Main execution
case $COMMAND in
    deploy)
        check_prerequisites
        setup_python_env
        bootstrap_cdk
        deploy_infrastructure
        ;;
    destroy)
        check_prerequisites
        setup_python_env
        destroy_infrastructure
        ;;
    status)
        check_prerequisites
        setup_python_env
        show_status
        ;;
    bootstrap)
        check_prerequisites
        bootstrap_cdk
        ;;
    setup)
        check_prerequisites
        setup_python_env
        ;;
    help)
        show_help
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac 
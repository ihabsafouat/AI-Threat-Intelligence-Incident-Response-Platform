#!/bin/bash

# Docker Manager Script for Threat Intelligence Platform
# This script helps manage different Docker configurations and services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
COMPOSE_FILE="docker-compose.services.yml"
SERVICES=""

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] COMMAND"
    echo ""
    echo "Commands:"
    echo "  up              Start all services"
    echo "  down            Stop all services"
    echo "  restart         Restart all services"
    echo "  build           Build all service images"
    echo "  logs            Show logs for all services"
    echo "  status          Show status of all services"
    echo "  clean           Clean up containers, images, and volumes"
    echo "  dev             Start development environment"
    echo "  prod            Start production environment"
    echo "  api             Start only API service"
    echo "  ingestion      Start only ingestion service"
    echo "  dashboard      Start only dashboard service"
    echo ""
    echo "Options:"
    echo "  -f, --file     Specify docker-compose file (default: docker-compose.services.yml)"
    echo "  -s, --services Specify services to run (comma-separated)"
    echo "  -h, --help     Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 up                    # Start all services"
    echo "  $0 dev                   # Start development environment"
    echo "  $0 prod                  # Start production environment"
    echo "  $0 -s api,ingestion up   # Start only API and ingestion services"
    echo "  $0 logs                  # Show logs for all services"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

# Function to check if docker-compose is available
check_docker_compose() {
    if ! command -v docker-compose > /dev/null 2>&1; then
        print_error "docker-compose is not installed. Please install it and try again."
        exit 1
    fi
}

# Function to start services
start_services() {
    local compose_cmd="docker-compose -f $COMPOSE_FILE up -d"
    
    if [ -n "$SERVICES" ]; then
        compose_cmd="$compose_cmd $SERVICES"
    fi
    
    print_status "Starting services using $COMPOSE_FILE..."
    print_status "Command: $compose_cmd"
    
    eval $compose_cmd
    
    if [ $? -eq 0 ]; then
        print_status "Services started successfully!"
        print_status "Use '$0 status' to check service status"
        print_status "Use '$0 logs' to view logs"
    else
        print_error "Failed to start services"
        exit 1
    fi
}

# Function to stop services
stop_services() {
    print_status "Stopping services..."
    docker-compose -f $COMPOSE_FILE down
    
    if [ $? -eq 0 ]; then
        print_status "Services stopped successfully!"
    else
        print_error "Failed to stop services"
        exit 1
    fi
}

# Function to restart services
restart_services() {
    print_status "Restarting services..."
    stop_services
    start_services
}

# Function to build services
build_services() {
    local compose_cmd="docker-compose -f $COMPOSE_FILE build"
    
    if [ -n "$SERVICES" ]; then
        compose_cmd="$compose_cmd $SERVICES"
    fi
    
    print_status "Building services..."
    print_status "Command: $compose_cmd"
    
    eval $compose_cmd
    
    if [ $? -eq 0 ]; then
        print_status "Services built successfully!"
    else
        print_error "Failed to build services"
        exit 1
    fi
}

# Function to show logs
show_logs() {
    local compose_cmd="docker-compose -f $COMPOSE_FILE logs -f"
    
    if [ -n "$SERVICES" ]; then
        compose_cmd="$compose_cmd $SERVICES"
    fi
    
    print_status "Showing logs..."
    print_status "Press Ctrl+C to stop following logs"
    
    eval $compose_cmd
}

# Function to show status
show_status() {
    print_status "Service status:"
    docker-compose -f $COMPOSE_FILE ps
    
    echo ""
    print_status "Service health:"
    docker-compose -f $COMPOSE_FILE ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
}

# Function to clean up
clean_up() {
    print_warning "This will remove all containers, images, and volumes. Are you sure? (y/N)"
    read -r response
    
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        print_status "Cleaning up..."
        
        # Stop and remove containers
        docker-compose -f $COMPOSE_FILE down -v
        
        # Remove all containers
        docker container prune -f
        
        # Remove all images
        docker image prune -a -f
        
        # Remove all volumes
        docker volume prune -f
        
        # Remove all networks
        docker network prune -f
        
        print_status "Cleanup completed!"
    else
        print_status "Cleanup cancelled."
    fi
}

# Function to start development environment
start_dev() {
    print_status "Starting development environment..."
    SERVICES="dashboard-dev,api,ingestion,celery_worker,celery_beat"
    start_services
}

# Function to start production environment
start_prod() {
    print_status "Starting production environment..."
    docker-compose -f $COMPOSE_FILE --profile production up -d
}

# Function to start specific service
start_specific_service() {
    local service=$1
    print_status "Starting $service service..."
    docker-compose -f $COMPOSE_FILE up -d $service
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--file)
            COMPOSE_FILE="$2"
            shift 2
            ;;
        -s|--services)
            SERVICES="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        up)
            COMMAND="up"
            shift
            ;;
        down)
            COMMAND="down"
            shift
            ;;
        restart)
            COMMAND="restart"
            shift
            ;;
        build)
            COMMAND="build"
            shift
            ;;
        logs)
            COMMAND="logs"
            shift
            ;;
        status)
            COMMAND="status"
            shift
            ;;
        clean)
            COMMAND="clean"
            shift
            ;;
        dev)
            COMMAND="dev"
            shift
            ;;
        prod)
            COMMAND="prod"
            shift
            ;;
        api)
            COMMAND="api"
            shift
            ;;
        ingestion)
            COMMAND="ingestion"
            shift
            ;;
        dashboard)
            COMMAND="dashboard"
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Check if command is provided
if [ -z "$COMMAND" ]; then
    print_error "No command specified"
    show_usage
    exit 1
fi

# Check prerequisites
check_docker
check_docker_compose

# Execute command
case $COMMAND in
    up)
        start_services
        ;;
    down)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    build)
        build_services
        ;;
    logs)
        show_logs
        ;;
    status)
        show_status
        ;;
    clean)
        clean_up
        ;;
    dev)
        start_dev
        ;;
    prod)
        start_prod
        ;;
    api)
        start_specific_service "api"
        ;;
    ingestion)
        start_specific_service "ingestion"
        ;;
    dashboard)
        start_specific_service "dashboard-dev"
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        show_usage
        exit 1
        ;;
esac 
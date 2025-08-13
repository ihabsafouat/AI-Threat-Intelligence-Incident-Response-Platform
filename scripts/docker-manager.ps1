# Docker Manager Script for Threat Intelligence Platform
# This script helps manage different Docker configurations and services

param(
    [string]$Command,
    [string]$ComposeFile = "docker-compose.services.yml",
    [string]$Services = ""
)

# Colors for output
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Blue"

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Red
}

function Write-Header {
    param([string]$Message)
    Write-Host "=== $Message ===" -ForegroundColor $Blue
}

# Function to show usage
function Show-Usage {
    Write-Host "Usage: .\docker-manager.ps1 [OPTIONS] COMMAND" -ForegroundColor $Blue
    Write-Host ""
    Write-Host "Commands:" -ForegroundColor $Blue
    Write-Host "  up              Start all services"
    Write-Host "  down            Stop all services"
    Write-Host "  restart         Restart all services"
    Write-Host "  build           Build all service images"
    Write-Host "  logs            Show logs for all services"
    Write-Host "  status          Show status of all services"
    Write-Host "  clean           Clean up containers, images, and volumes"
    Write-Host "  dev             Start development environment"
    Write-Host "  prod            Start production environment"
    Write-Host "  api             Start only API service"
    Write-Host "  ingestion      Start only ingestion service"
    Write-Host "  dashboard      Start only dashboard service"
    Write-Host ""
    Write-Host "Options:" -ForegroundColor $Blue
    Write-Host "  -ComposeFile    Specify docker-compose file (default: docker-compose.services.yml)"
    Write-Host "  -Services       Specify services to run (comma-separated)"
    Write-Host "  -Command        Command to execute"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor $Blue
    Write-Host "  .\docker-manager.ps1 -Command up                    # Start all services"
    Write-Host "  .\docker-manager.ps1 -Command dev                   # Start development environment"
    Write-Host "  .\docker-manager.ps1 -Command prod                  # Start production environment"
    Write-Host "  .\docker-manager.ps1 -Command up -Services api,ingestion   # Start only API and ingestion services"
    Write-Host "  .\docker-manager.ps1 -Command logs                  # Show logs for all services"
}

# Function to check if Docker is running
function Test-Docker {
    try {
        docker info | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Function to check if docker-compose is available
function Test-DockerCompose {
    try {
        docker-compose --version | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Function to start services
function Start-Services {
    $composeCmd = "docker-compose -f $ComposeFile up -d"
    
    if ($Services) {
        $composeCmd += " $Services"
    }
    
    Write-Status "Starting services using $ComposeFile..."
    Write-Status "Command: $composeCmd"
    
    try {
        Invoke-Expression $composeCmd
        Write-Status "Services started successfully!"
        Write-Status "Use '.\docker-manager.ps1 -Command status' to check service status"
        Write-Status "Use '.\docker-manager.ps1 -Command logs' to view logs"
    }
    catch {
        Write-Error "Failed to start services"
        exit 1
    }
}

# Function to stop services
function Stop-Services {
    Write-Status "Stopping services..."
    try {
        docker-compose -f $ComposeFile down
        Write-Status "Services stopped successfully!"
    }
    catch {
        Write-Error "Failed to stop services"
        exit 1
    }
}

# Function to restart services
function Restart-Services {
    Write-Status "Restarting services..."
    Stop-Services
    Start-Services
}

# Function to build services
function Build-Services {
    $composeCmd = "docker-compose -f $ComposeFile build"
    
    if ($Services) {
        $composeCmd += " $Services"
    }
    
    Write-Status "Building services..."
    Write-Status "Command: $composeCmd"
    
    try {
        Invoke-Expression $composeCmd
        Write-Status "Services built successfully!"
    }
    catch {
        Write-Error "Failed to build services"
        exit 1
    }
}

# Function to show logs
function Show-Logs {
    $composeCmd = "docker-compose -f $ComposeFile logs -f"
    
    if ($Services) {
        $composeCmd += " $Services"
    }
    
    Write-Status "Showing logs..."
    Write-Status "Press Ctrl+C to stop following logs"
    
    Invoke-Expression $composeCmd
}

# Function to show status
function Show-Status {
    Write-Status "Service status:"
    docker-compose -f $ComposeFile ps
    
    Write-Host ""
    Write-Status "Service health:"
    docker-compose -f $ComposeFile ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
}

# Function to clean up
function Clean-Up {
    $response = Read-Host "This will remove all containers, images, and volumes. Are you sure? (y/N)"
    
    if ($response -match "^[yY](es)?$") {
        Write-Status "Cleaning up..."
        
        # Stop and remove containers
        docker-compose -f $ComposeFile down -v
        
        # Remove all containers
        docker container prune -f
        
        # Remove all images
        docker image prune -a -f
        
        # Remove all volumes
        docker volume prune -f
        
        # Remove all networks
        docker network prune -f
        
        Write-Status "Cleanup completed!"
    }
    else {
        Write-Status "Cleanup cancelled."
    }
}

# Function to start development environment
function Start-Dev {
    Write-Status "Starting development environment..."
    $script:Services = "dashboard-dev,api,ingestion,celery_worker,celery_beat"
    Start-Services
}

# Function to start production environment
function Start-Prod {
    Write-Status "Starting production environment..."
    docker-compose -f $ComposeFile --profile production up -d
}

# Function to start specific service
function Start-SpecificService {
    param([string]$Service)
    Write-Status "Starting $Service service..."
    docker-compose -f $ComposeFile up -d $Service
}

# Main execution
if (-not $Command) {
    Write-Error "No command specified"
    Show-Usage
    exit 1
}

# Check prerequisites
if (-not (Test-Docker)) {
    Write-Error "Docker is not running. Please start Docker and try again."
    exit 1
}

if (-not (Test-DockerCompose)) {
    Write-Error "docker-compose is not installed. Please install it and try again."
    exit 1
}

# Execute command
switch ($Command.ToLower()) {
    "up" {
        Start-Services
    }
    "down" {
        Stop-Services
    }
    "restart" {
        Restart-Services
    }
    "build" {
        Build-Services
    }
    "logs" {
        Show-Logs
    }
    "status" {
        Show-Status
    }
    "clean" {
        Clean-Up
    }
    "dev" {
        Start-Dev
    }
    "prod" {
        Start-Prod
    }
    "api" {
        Start-SpecificService "api"
    }
    "ingestion" {
        Start-SpecificService "ingestion"
    }
    "dashboard" {
        Start-SpecificService "dashboard-dev"
    }
    default {
        Write-Error "Unknown command: $Command"
        Show-Usage
        exit 1
    }
} 
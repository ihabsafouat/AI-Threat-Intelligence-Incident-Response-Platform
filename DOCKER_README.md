# Docker Configuration for Threat Intelligence Platform

This document describes the Docker setup for the Threat Intelligence Platform, including dedicated Dockerfiles for each service type and optimized docker-compose configurations.

## Service Architecture

The platform consists of the following services:

1. **API Service** (`backend/Dockerfile.api`) - FastAPI backend for HTTP requests
2. **Ingestion Service** (`backend/Dockerfile.ingestion`) - Data processing and ETL pipeline
3. **Dashboard** (`frontend/Dockerfile.development`, `frontend/Dockerfile.production`) - React/Next.js frontend
4. **Worker Services** (`backend/Dockerfile.worker`) - Celery workers for background tasks
5. **Infrastructure** - PostgreSQL, Redis, Airflow

## Dockerfiles Overview

### Backend Services

#### `Dockerfile.api` - API Service
- **Purpose**: Optimized for serving HTTP requests
- **Port**: 8000
- **Features**: 
  - Multi-worker uvicorn setup (4 workers)
  - Optimized for API performance
  - Minimal system dependencies

#### `Dockerfile.ingestion` - Ingestion Service
- **Purpose**: Data processing and ETL operations
- **Port**: 8001
- **Features**:
  - Extended system dependencies for data processing
  - PDF processing (poppler-utils)
  - Excel processing (libreoffice)
  - Image processing support
  - Dedicated data directories

#### `Dockerfile.worker` - Worker Services
- **Purpose**: Background task processing (Celery)
- **Features**:
  - Optimized for task processing
  - Health checks via Celery inspect
  - Flexible command override

### Frontend Services

#### `Dockerfile.development` - Development Dashboard
- **Purpose**: Development environment with hot reloading
- **Port**: 3000
- **Features**:
  - Volume mounting for live code changes
  - Development dependencies included
  - Hot reloading enabled

#### `Dockerfile.production` - Production Dashboard
- **Purpose**: Production-optimized frontend
- **Port**: 3001 (when using production profile)
- **Features**:
  - Multi-stage build for smaller image size
  - Production dependencies only
  - Built application copied from builder stage
  - Signal handling with dumb-init

## Docker Compose Configurations

### `docker-compose.yml` (Original)
- Uses single Dockerfile for multiple backend services
- Good for simple deployments

### `docker-compose.services.yml` (New)
- Dedicated Dockerfiles for each service type
- Better separation of concerns
- Optimized for each service's specific needs

## Usage

### Development Environment

```bash
# Start development services
docker-compose -f docker-compose.services.yml up dashboard-dev api ingestion

# Start all services (development)
docker-compose -f docker-compose.services.yml up
```

### Production Environment

```bash
# Start production services
docker-compose -f docker-compose.services.yml --profile production up

# Start with nginx reverse proxy
docker-compose -f docker-compose.services.yml --profile production up nginx
```

### Service-Specific Commands

```bash
# Build specific service
docker-compose -f docker-compose.services.yml build api
docker-compose -f docker-compose.services.yml build ingestion
docker-compose -f docker-compose.services.yml build dashboard-prod

# Run specific service
docker-compose -f docker-compose.services.yml up ingestion
```

## Service Ports

| Service | Port | Description |
|---------|------|-------------|
| API | 8000 | Backend API endpoints |
| Ingestion | 8001 | Data processing service |
| Dashboard Dev | 3000 | Development frontend |
| Dashboard Prod | 3001 | Production frontend |
| PostgreSQL | 5432 | Database |
| Redis | 6379 | Cache |
| Airflow | 8080 | Workflow management |

## Environment Variables

Create a `.env` file in the root directory:

```bash
# AWS Configuration
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1
S3_BUCKET=your_bucket_name

# Database (optional, defaults provided)
DATABASE_URL=postgresql://threat_user:threat_password@postgres:5432/threat_intel
REDIS_URL=redis://redis:6379
```

## Health Checks

All services include health checks:

- **API Service**: HTTP endpoint `/health`
- **Ingestion Service**: HTTP endpoint `/health`
- **Dashboard**: HTTP endpoint `/`
- **Workers**: Celery inspect ping
- **Database**: PostgreSQL connection check
- **Redis**: Redis ping command

## Volume Mounts

### Backend Services
- `./backend:/app` - Source code
- `./uploads:/app/uploads` - File uploads
- `./logs:/app/logs` - Application logs
- `./temp_data:/app/temp_data` - Temporary data (ingestion/workers)
- `./processed_data:/app/processed_data` - Processed data (ingestion)

### Frontend Services
- `./frontend:/app` - Source code (development)
- `/app/node_modules` - Node modules (development)

## Building Images

### Individual Services

```bash
# Build API service
docker build -f backend/Dockerfile.api -t threat-intel-api ./backend

# Build ingestion service
docker build -f backend/Dockerfile.ingestion -t threat-intel-ingestion ./backend

# Build dashboard (development)
docker build -f frontend/Dockerfile.development -t threat-intel-dashboard-dev ./frontend

# Build dashboard (production)
docker build -f frontend/Dockerfile.production -t threat-intel-dashboard-prod ./frontend
```

### All Services

```bash
# Build all services
docker-compose -f docker-compose.services.yml build

# Build with no cache
docker-compose -f docker-compose.services.yml build --no-cache
```

## Monitoring and Logs

### View Logs

```bash
# All services
docker-compose -f docker-compose.services.yml logs

# Specific service
docker-compose -f docker-compose.services.yml logs ingestion
docker-compose -f docker-compose.services.yml logs api
```

### Service Status

```bash
# Check service health
docker-compose -f docker-compose.services.yml ps

# Check specific service health
docker inspect threat_intel_ingestion | grep Health -A 10
```

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Ensure ports are not already in use
2. **Permission Issues**: Check file ownership for mounted volumes
3. **Memory Issues**: Increase Docker memory allocation for large data processing
4. **Build Failures**: Check `.dockerignore` files and build context

### Debug Mode

```bash
# Run with debug output
docker-compose -f docker-compose.services.yml up --verbose

# Run service in interactive mode
docker-compose -f docker-compose.services.yml run --rm ingestion bash
```

## Performance Optimization

### API Service
- Uses 4 uvicorn workers for better concurrency
- Optimized system dependencies

### Ingestion Service
- Extended system tools for data processing
- Dedicated data directories for better I/O

### Dashboard
- Multi-stage build reduces image size
- Production build excludes development dependencies

### Workers
- Optimized for background task processing
- Minimal overhead for task execution

## Security Considerations

- All services run as non-root users
- Health checks prevent unhealthy containers from receiving traffic
- Environment variables for sensitive configuration
- Network isolation between services 
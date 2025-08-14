# CI/CD Pipeline Documentation

This document describes the comprehensive CI/CD pipeline setup for the Threat Intelligence Platform using GitHub Actions.

## Overview

The CI/CD pipeline consists of multiple workflows that handle different aspects of the development and deployment process:

1. **Main CI/CD Pipeline** (`ci-cd.yml`) - Comprehensive testing, building, and deployment
2. **Docker Build & Push** (`docker-build.yml`) - Dedicated Docker image building
3. **Test & Quality Checks** (`test.yml`) - Testing and code quality validation
4. **Deployment** (`deploy.yml`) - Staging and production deployments
5. **Security & Dependency Management** (`security.yml`) - Security scanning and dependency updates

## Workflow Triggers

### Automatic Triggers
- **Push to main/develop**: Runs tests, builds images, deploys to staging
- **Push tags (v*)**: Deploys to production
- **Pull Requests**: Runs tests and security scans
- **Scheduled**: Daily security scans, weekly tests

### Manual Triggers
- **Workflow Dispatch**: Manual execution with custom parameters
- **Release Creation**: Production deployments

## Workflow Details

### 1. Main CI/CD Pipeline (`ci-cd.yml`)

**Purpose**: End-to-end pipeline for testing, building, and deploying

**Jobs**:
- **Test**: Runs backend and frontend tests
- **Build**: Builds Docker images for all services
- **Security**: Scans built images for vulnerabilities
- **Deploy Staging**: Deploys to staging environment
- **Deploy Production**: Deploys to production environment

**Features**:
- Matrix builds for multiple services
- Multi-platform Docker builds (amd64, arm64)
- Automated tagging and labeling
- Health checks and smoke tests

### 2. Docker Build & Push (`docker-build.yml`)

**Purpose**: Dedicated workflow for building and pushing Docker images

**Services Built**:
- `api` - Backend API service
- `ingestion` - Data processing service
- `worker` - Celery worker service
- `dashboard-dev` - Development frontend
- `dashboard-prod` - Production frontend

**Features**:
- GitHub Container Registry integration
- SBOM (Software Bill of Materials) generation
- Vulnerability scanning with Trivy
- Multi-platform builds
- Manual trigger with service selection

### 3. Test & Quality Checks (`test.yml`)

**Purpose**: Comprehensive testing and code quality validation

**Jobs**:
- **Backend Tests**: Python linting, security checks, unit tests
- **Frontend Tests**: Node.js linting, type checking, unit tests
- **Integration Tests**: End-to-end testing with databases
- **Performance Tests**: Load testing and benchmarking
- **Dependency Scan**: Vulnerability scanning
- **Code Quality Report**: Coverage and quality metrics

**Tools Used**:
- **Python**: pytest, flake8, black, isort, mypy, bandit, safety
- **Node.js**: ESLint, TypeScript, Jest
- **Security**: Snyk, Trivy
- **Performance**: Locust, pytest-benchmark

### 4. Deployment (`deploy.yml`)

**Purpose**: Automated deployment to staging and production

**Environments**:
- **Staging**: Automatic deployment from develop branch
- **Production**: Manual deployment from version tags

**Features**:
- Kubernetes deployment
- AWS EKS integration
- Health checks and smoke tests
- Automatic rollback on failure
- Performance testing in production

### 5. Security & Dependency Management (`security.yml`)

**Purpose**: Security scanning and dependency management

**Jobs**:
- **Dependency Scan**: Snyk vulnerability scanning
- **Container Scan**: Trivy container vulnerability scanning
- **Code Security**: Bandit and Semgrep security analysis
- **Dependency Updates**: Automated dependency update PRs
- **License Compliance**: License checking and reporting
- **Security Policy**: Policy validation and secret detection

## Docker Images

### Image Naming Convention
```
ghcr.io/{repository}/{service}:{tag}
```

### Available Images
- `ghcr.io/{repo}/api` - Backend API service
- `ghcr.io/{repo}/ingestion` - Data ingestion service
- `ghcr.io/{repo}/worker` - Celery worker service
- `ghcr.io/{repo}/dashboard-dev` - Development dashboard
- `ghcr.io/{repo}/dashboard-prod` - Production dashboard

### Image Tags
- `latest` - Latest stable version
- `main` - Latest from main branch
- `develop` - Latest from develop branch
- `v1.0.0` - Version tags
- `{branch}-{sha}` - Branch-specific builds

## Environment Configuration

### Required Secrets

#### GitHub Secrets
```bash
# AWS Configuration
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_REGION

# EKS Clusters
EKS_CLUSTER_STAGING
EKS_CLUSTER_PRODUCTION

# Security Tools
SNYK_TOKEN

# Container Registry (optional, uses GITHUB_TOKEN by default)
REGISTRY_USERNAME
REGISTRY_PASSWORD
```

#### Environment Variables
```bash
# Application Configuration
DATABASE_URL
REDIS_URL
SECRET_KEY
JWT_SECRET_KEY

# AWS Configuration
AWS_REGION
S3_BUCKET

# Feature Flags
DEBUG
TESTING
```

## Usage Examples

### Manual Workflow Execution

#### Build Specific Service
```bash
# Via GitHub UI: Actions > Docker Build and Push > Run workflow
# Select service: api, ingestion, worker, dashboard-dev, dashboard-prod, or all
```

#### Deploy to Specific Environment
```bash
# Via GitHub UI: Actions > Deploy > Run workflow
# Select environment: staging or production
# Select service: all, api, ingestion, worker, or dashboard
```

### Local Development

#### Using Docker Compose
```bash
# Development environment
docker-compose -f docker-compose.services.yml up dashboard-dev api ingestion

# Production environment
docker-compose -f docker-compose.services.yml --profile production up
```

#### Using Management Scripts
```bash
# PowerShell (Windows)
.\scripts\docker-manager.ps1 -Command dev
.\scripts\docker-manager.ps1 -Command prod

# Bash (Linux/Mac)
./scripts/docker-manager.sh dev
./scripts/docker-manager.sh prod
```

## Monitoring and Observability

### Health Checks
- **API Service**: `GET /health`
- **Ingestion Service**: `GET /health`
- **Dashboard**: `GET /`
- **Workers**: Celery inspect ping

### Metrics and Logs
- **Application Logs**: Available in container logs
- **Performance Metrics**: Generated during deployment
- **Security Reports**: Uploaded as artifacts
- **Coverage Reports**: Available for download

### Alerts and Notifications
- **Deployment Success/Failure**: Console output
- **Security Vulnerabilities**: GitHub Security tab
- **Test Failures**: Workflow status
- **Performance Issues**: Performance test reports

## Best Practices

### Development Workflow
1. **Feature Development**: Create feature branch from develop
2. **Testing**: Run tests locally before pushing
3. **Pull Request**: Create PR with comprehensive description
4. **Code Review**: Address review comments
5. **Merge**: Merge to develop for staging deployment
6. **Release**: Create version tag for production deployment

### Security Practices
1. **Regular Scans**: Daily security scans
2. **Dependency Updates**: Weekly automated updates
3. **Vulnerability Management**: Immediate response to high/critical issues
4. **Secret Management**: Use GitHub secrets for sensitive data
5. **Access Control**: Environment protection rules

### Deployment Practices
1. **Staging First**: Always deploy to staging before production
2. **Health Checks**: Verify service health after deployment
3. **Rollback Plan**: Automatic rollback on failure
4. **Monitoring**: Monitor deployments and performance
5. **Documentation**: Update deployment documentation

## Troubleshooting

### Common Issues

#### Build Failures
```bash
# Check Docker build logs
docker-compose -f docker-compose.services.yml build --no-cache

# Verify Dockerfile syntax
docker build --dry-run -f backend/Dockerfile.api ./backend
```

#### Test Failures
```bash
# Run tests locally
cd backend && pytest
cd frontend && npm test

# Check test coverage
cd backend && pytest --cov=app --cov-report=html
```

#### Deployment Issues
```bash
# Check Kubernetes status
kubectl get pods -n threat-intel-staging
kubectl describe pod <pod-name> -n threat-intel-staging

# Check service logs
kubectl logs <pod-name> -n threat-intel-staging
```

#### Security Issues
```bash
# Run security scans locally
cd backend && bandit -r app/
cd frontend && npm audit

# Check for vulnerabilities
safety check
```

### Debug Mode
```bash
# Enable debug logging
export DEBUG=true
export LOG_LEVEL=DEBUG

# Run with verbose output
docker-compose -f docker-compose.services.yml up --verbose
```

## Performance Optimization

### Build Optimization
- **Multi-stage builds**: Reduce image size
- **Layer caching**: Optimize build times
- **Parallel builds**: Matrix strategy for multiple services
- **Build cache**: GitHub Actions cache for dependencies

### Runtime Optimization
- **Resource limits**: CPU and memory constraints
- **Health checks**: Prevent unhealthy containers
- **Load balancing**: Multiple worker processes
- **Caching**: Redis for session and data caching

### Monitoring Optimization
- **Metrics collection**: Prometheus integration
- **Log aggregation**: Centralized logging
- **Alerting**: Proactive issue detection
- **Performance tracking**: Continuous monitoring

## Future Enhancements

### Planned Features
1. **Blue-Green Deployments**: Zero-downtime deployments
2. **Canary Releases**: Gradual rollout with monitoring
3. **Infrastructure as Code**: Terraform integration
4. **Service Mesh**: Istio integration for advanced routing
5. **Chaos Engineering**: Resilience testing
6. **Cost Optimization**: Resource usage monitoring
7. **Multi-Region**: Geographic distribution
8. **Disaster Recovery**: Automated backup and recovery

### Integration Opportunities
1. **Slack Notifications**: Deployment status updates
2. **Jira Integration**: Issue tracking and automation
3. **SonarQube**: Advanced code quality analysis
4. **Grafana**: Advanced monitoring dashboards
5. **ELK Stack**: Enhanced logging and analysis 
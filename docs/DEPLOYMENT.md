# Deployment Guide

This guide provides comprehensive instructions for deploying the AI Threat Intelligence & Incident Response Platform across different environments and cloud providers.

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development Deployment](#local-development-deployment)
3. [Docker Deployment](#docker-deployment)
4. [Cloud Deployment](#cloud-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Production Considerations](#production-considerations)
7. [Monitoring & Maintenance](#monitoring--maintenance)
8. [Troubleshooting](#troubleshooting)

## 🔧 Prerequisites

### System Requirements
- **CPU**: 4+ cores (8+ recommended for production)
- **RAM**: 8GB+ (16GB+ recommended for production)
- **Storage**: 50GB+ available space
- **Network**: Stable internet connection for external APIs

### Software Requirements
- **Docker**: 20.10+ (for containerized deployment)
- **Docker Compose**: 2.0+ (for local deployment)
- **Python**: 3.11+ (for backend)
- **Node.js**: 18+ (for frontend)
- **PostgreSQL**: 15+ (for database)
- **Redis**: 7+ (for caching)

### Cloud Requirements
- **AWS Account** (for AWS deployment)
- **Azure Subscription** (for Azure deployment)
- **GCP Project** (for GCP deployment)
- **Domain Name** (for production)

## 🏠 Local Development Deployment

### Step 1: Clone and Setup
```bash
# Clone the repository
git clone https://github.com/your-org/threat-intelligence-platform.git
cd threat-intelligence-platform

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 2: Backend Setup
```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env

# Edit environment variables
nano .env  # or use your preferred editor
```

**Required Environment Variables:**
```env
# Database
DATABASE_URL=postgresql://user:password@localhost/threat_intel

# Redis
REDIS_URL=redis://localhost:6379

# Security
SECRET_KEY=your-super-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here

# External APIs
CVE_API_KEY=your-cve-api-key
THREAT_FEED_API_KEY=your-threat-feed-key

# Application
DEBUG=True
ENVIRONMENT=development
```

### Step 3: Database Setup
```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt update
sudo apt install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql
CREATE DATABASE threat_intel;
CREATE USER threat_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE threat_intel TO threat_user;
\q

# Run migrations
alembic upgrade head
```

### Step 4: Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Create environment file
cp .env.example .env

# Edit environment variables
nano .env
```

**Frontend Environment Variables:**
```env
REACT_APP_API_URL=http://localhost:8000
REACT_APP_ENVIRONMENT=development
```

### Step 5: Start Services
```bash
# Terminal 1: Start PostgreSQL
sudo systemctl start postgresql

# Terminal 2: Start Redis
redis-server

# Terminal 3: Start Backend
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Terminal 4: Start Frontend
cd frontend
npm start
```

### Step 6: Verify Deployment
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

## 🐳 Docker Deployment

### Option 1: Docker Compose (Recommended for Development)

#### Step 1: Create Docker Compose File
```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: threat_intel
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: your_secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    networks:
      - threat_intel_network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    networks:
      - threat_intel_network

  backend:
    build: 
      context: ./backend
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql://postgres:your_secure_password@postgres/threat_intel
      REDIS_URL: redis://redis:6379
      SECRET_KEY: your-super-secret-key-here
      JWT_SECRET_KEY: your-jwt-secret-key-here
      CVE_API_KEY: your-cve-api-key
      THREAT_FEED_API_KEY: your-threat-feed-key
      DEBUG: False
      ENVIRONMENT: production
    depends_on:
      - postgres
      - redis
    ports:
      - "8000:8000"
    networks:
      - threat_intel_network
    restart: unless-stopped

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    environment:
      REACT_APP_API_URL: http://localhost:8000
      REACT_APP_ENVIRONMENT: production
    ports:
      - "3000:3000"
    depends_on:
      - backend
    networks:
      - threat_intel_network
    restart: unless-stopped

volumes:
  postgres_data:

networks:
  threat_intel_network:
    driver: bridge
```

#### Step 2: Create Dockerfiles

**Backend Dockerfile:**
```dockerfile
# backend/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Run migrations
RUN alembic upgrade head

# Expose port
EXPOSE 8000

# Start application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Frontend Dockerfile:**
```dockerfile
# frontend/Dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY . .

# Build application
RUN npm run build

# Install serve
RUN npm install -g serve

# Expose port
EXPOSE 3000

# Start application
CMD ["serve", "-s", "build", "-l", "3000"]
```

#### Step 3: Deploy with Docker Compose
```bash
# Build and start services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Option 2: Individual Docker Containers

#### Step 1: Build Images
```bash
# Build backend image
docker build -t threat-intel-backend ./backend

# Build frontend image
docker build -t threat-intel-frontend ./frontend
```

#### Step 2: Run Containers
```bash
# Create network
docker network create threat_intel_network

# Run PostgreSQL
docker run -d \
  --name postgres \
  --network threat_intel_network \
  -e POSTGRES_DB=threat_intel \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=your_secure_password \
  -v postgres_data:/var/lib/postgresql/data \
  -p 5432:5432 \
  postgres:15

# Run Redis
docker run -d \
  --name redis \
  --network threat_intel_network \
  -p 6379:6379 \
  redis:7-alpine

# Run Backend
docker run -d \
  --name backend \
  --network threat_intel_network \
  -e DATABASE_URL=postgresql://postgres:your_secure_password@postgres/threat_intel \
  -e REDIS_URL=redis://redis:6379 \
  -e SECRET_KEY=your-super-secret-key-here \
  -e JWT_SECRET_KEY=your-jwt-secret-key-here \
  -p 8000:8000 \
  threat-intel-backend

# Run Frontend
docker run -d \
  --name frontend \
  --network threat_intel_network \
  -e REACT_APP_API_URL=http://localhost:8000 \
  -p 3000:3000 \
  threat-intel-frontend
```

## ☁️ Cloud Deployment

### AWS Deployment

#### Option 1: AWS ECS with Fargate

**Step 1: Create ECR Repositories**
```bash
# Create repositories
aws ecr create-repository --repository-name threat-intel-backend
aws ecr create-repository --repository-name threat-intel-frontend

# Get login token
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin your-account-id.dkr.ecr.us-east-1.amazonaws.com

# Tag and push images
docker tag threat-intel-backend:latest your-account-id.dkr.ecr.us-east-1.amazonaws.com/threat-intel-backend:latest
docker tag threat-intel-frontend:latest your-account-id.dkr.ecr.us-east-1.amazonaws.com/threat-intel-frontend:latest

docker push your-account-id.dkr.ecr.us-east-1.amazonaws.com/threat-intel-backend:latest
docker push your-account-id.dkr.ecr.us-east-1.amazonaws.com/threat-intel-frontend:latest
```

**Step 2: Create ECS Task Definitions**
```json
// backend-task-definition.json
{
  "family": "threat-intel-backend",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::your-account-id:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "backend",
      "image": "your-account-id.dkr.ecr.us-east-1.amazonaws.com/threat-intel-backend:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "DATABASE_URL",
          "value": "postgresql://user:password@your-rds-endpoint/threat_intel"
        },
        {
          "name": "REDIS_URL",
          "value": "redis://your-elasticache-endpoint:6379"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/threat-intel-backend",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

**Step 3: Create ECS Services**
```bash
# Register task definition
aws ecs register-task-definition --cli-input-json file://backend-task-definition.json

# Create service
aws ecs create-service \
  --cluster threat-intel-cluster \
  --service-name backend-service \
  --task-definition threat-intel-backend:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-12345,subnet-67890],securityGroups=[sg-12345],assignPublicIp=ENABLED}"
```

#### Option 2: AWS EKS (Kubernetes)

**Step 1: Create EKS Cluster**
```bash
# Create cluster
eksctl create cluster \
  --name threat-intel-cluster \
  --region us-east-1 \
  --nodegroup-name standard-workers \
  --node-type t3.medium \
  --nodes 3 \
  --nodes-min 1 \
  --nodes-max 4 \
  --managed
```

**Step 2: Deploy with Kubernetes Manifests**
```bash
# Apply manifests
kubectl apply -f infrastructure/kubernetes/namespace.yaml
kubectl apply -f infrastructure/kubernetes/postgres.yaml
kubectl apply -f infrastructure/kubernetes/redis.yaml
kubectl apply -f infrastructure/kubernetes/backend.yaml
kubectl apply -f infrastructure/kubernetes/frontend.yaml
```

### Azure Deployment

#### Option 1: Azure Container Instances

**Step 1: Create Azure Container Registry**
```bash
# Create resource group
az group create --name threat-intel-rg --location eastus

# Create container registry
az acr create --resource-group threat-intel-rg --name threatintelacr --sku Basic

# Build and push images
az acr build --registry threatintelacr --image threat-intel-backend:latest ./backend
az acr build --registry threatintelacr --image threat-intel-frontend:latest ./frontend
```

**Step 2: Deploy with Azure Container Instances**
```bash
# Deploy backend
az container create \
  --resource-group threat-intel-rg \
  --name backend-container \
  --image threatintelacr.azurecr.io/threat-intel-backend:latest \
  --dns-name-label threat-intel-backend \
  --ports 8000 \
  --environment-variables \
    DATABASE_URL="postgresql://user:password@your-postgres-server.postgres.database.azure.com/threat_intel" \
    REDIS_URL="redis://your-redis-cache.redis.cache.windows.net:6380"

# Deploy frontend
az container create \
  --resource-group threat-intel-rg \
  --name frontend-container \
  --image threatintelacr.azurecr.io/threat-intel-frontend:latest \
  --dns-name-label threat-intel-frontend \
  --ports 3000 \
  --environment-variables \
    REACT_APP_API_URL="http://threat-intel-backend.eastus.azurecontainer.io:8000"
```

#### Option 2: Azure Kubernetes Service (AKS)

**Step 1: Create AKS Cluster**
```bash
# Create AKS cluster
az aks create \
  --resource-group threat-intel-rg \
  --name threat-intel-aks \
  --node-count 3 \
  --enable-addons monitoring \
  --generate-ssh-keys

# Get credentials
az aks get-credentials --resource-group threat-intel-rg --name threat-intel-aks
```

**Step 2: Deploy with Helm**
```bash
# Create Helm chart
helm create threat-intel

# Deploy with Helm
helm install threat-intel ./threat-intel \
  --set backend.image.repository=threatintelacr.azurecr.io/threat-intel-backend \
  --set frontend.image.repository=threatintelacr.azurecr.io/threat-intel-frontend
```

### GCP Deployment

#### Option 1: Google Cloud Run

**Step 1: Build and Push Images**
```bash
# Configure Docker for GCR
gcloud auth configure-docker

# Build and push images
docker build -t gcr.io/your-project-id/threat-intel-backend ./backend
docker build -t gcr.io/your-project-id/threat-intel-frontend ./frontend

docker push gcr.io/your-project-id/threat-intel-backend
docker push gcr.io/your-project-id/threat-intel-frontend
```

**Step 2: Deploy to Cloud Run**
```bash
# Deploy backend
gcloud run deploy threat-intel-backend \
  --image gcr.io/your-project-id/threat-intel-backend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars DATABASE_URL="postgresql://user:password@your-cloud-sql-instance/threat_intel"

# Deploy frontend
gcloud run deploy threat-intel-frontend \
  --image gcr.io/your-project-id/threat-intel-frontend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars REACT_APP_API_URL="https://threat-intel-backend-xxxxx-uc.a.run.app"
```

#### Option 2: Google Kubernetes Engine (GKE)

**Step 1: Create GKE Cluster**
```bash
# Create cluster
gcloud container clusters create threat-intel-cluster \
  --zone us-central1-a \
  --num-nodes 3 \
  --machine-type n1-standard-2

# Get credentials
gcloud container clusters get-credentials threat-intel-cluster --zone us-central1-a
```

**Step 2: Deploy with Kubernetes**
```bash
# Apply manifests
kubectl apply -f infrastructure/kubernetes/namespace.yaml
kubectl apply -f infrastructure/kubernetes/postgres.yaml
kubectl apply -f infrastructure/kubernetes/redis.yaml
kubectl apply -f infrastructure/kubernetes/backend.yaml
kubectl apply -f infrastructure/kubernetes/frontend.yaml
```

## ☸️ Kubernetes Deployment

### Prerequisites
- Kubernetes cluster (1.20+)
- kubectl configured
- Helm (optional)

### Step 1: Create Namespace
```yaml
# infrastructure/kubernetes/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: threat-intel
  labels:
    name: threat-intel
```

### Step 2: Database Deployment
```yaml
# infrastructure/kubernetes/postgres.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: threat-intel
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        env:
        - name: POSTGRES_DB
          value: "threat_intel"
        - name: POSTGRES_USER
          value: "postgres"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: threat-intel
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
```

### Step 3: Redis Deployment
```yaml
# infrastructure/kubernetes/redis.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: threat-intel
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: threat-intel
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
  type: ClusterIP
```

### Step 4: Backend Deployment
```yaml
# infrastructure/kubernetes/backend.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: threat-intel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: backend
        image: threat-intel-backend:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          value: "postgresql://postgres:$(POSTGRES_PASSWORD)@postgres/threat_intel"
        - name: REDIS_URL
          value: "redis://redis:6379"
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: secret-key
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: jwt-secret-key
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: backend-service
  namespace: threat-intel
spec:
  selector:
    app: backend
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

### Step 5: Frontend Deployment
```yaml
# infrastructure/kubernetes/frontend.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: threat-intel
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: frontend
        image: threat-intel-frontend:latest
        ports:
        - containerPort: 3000
        env:
        - name: REACT_APP_API_URL
          value: "http://backend-service"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "200m"
        livenessProbe:
          httpGet:
            path: /
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: frontend-service
  namespace: threat-intel
spec:
  selector:
    app: frontend
  ports:
  - port: 80
    targetPort: 3000
  type: LoadBalancer
```

### Step 6: Apply Manifests
```bash
# Create secrets first
kubectl create secret generic postgres-secret \
  --from-literal=password=your_secure_password \
  --namespace threat-intel

kubectl create secret generic app-secrets \
  --from-literal=secret-key=your-super-secret-key \
  --from-literal=jwt-secret-key=your-jwt-secret-key \
  --namespace threat-intel

# Apply all manifests
kubectl apply -f infrastructure/kubernetes/
```

## 🏭 Production Considerations

### Security
- Use HTTPS/TLS for all communications
- Implement proper authentication and authorization
- Use secrets management for sensitive data
- Enable audit logging
- Regular security updates

### Performance
- Use load balancers for high availability
- Implement caching strategies
- Optimize database queries
- Use CDN for static assets
- Monitor and scale based on metrics

### Monitoring
- Set up application monitoring (Prometheus, Grafana)
- Configure log aggregation (ELK stack)
- Set up alerting for critical issues
- Monitor resource usage
- Track application metrics

### Backup & Recovery
- Regular database backups
- Configuration backup
- Disaster recovery plan
- Test recovery procedures

## 📊 Monitoring & Maintenance

### Health Checks
```bash
# Check application health
curl http://your-app-url/health

# Check database connectivity
curl http://your-app-url/health/db

# Check Redis connectivity
curl http://your-app-url/health/redis
```

### Log Monitoring
```bash
# View application logs
kubectl logs -f deployment/backend -n threat-intel

# View frontend logs
kubectl logs -f deployment/frontend -n threat-intel

# View database logs
kubectl logs -f statefulset/postgres -n threat-intel
```

### Performance Monitoring
```bash
# Run stress tests
cd scripts
./run_comprehensive_stress_test.sh comprehensive

# Monitor system resources
python3 monitor_system_performance.py --duration 3600 --summary
```

### Updates & Maintenance
```bash
# Update application
kubectl set image deployment/backend backend=threat-intel-backend:latest -n threat-intel
kubectl set image deployment/frontend frontend=threat-intel-frontend:latest -n threat-intel

# Rollback if needed
kubectl rollout undo deployment/backend -n threat-intel
kubectl rollout undo deployment/frontend -n threat-intel
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Database Connection Issues
```bash
# Check database status
kubectl get pods -n threat-intel | grep postgres

# Check database logs
kubectl logs postgres-0 -n threat-intel

# Test database connection
kubectl exec -it postgres-0 -n threat-intel -- psql -U postgres -d threat_intel
```

#### 2. Redis Connection Issues
```bash
# Check Redis status
kubectl get pods -n threat-intel | grep redis

# Test Redis connection
kubectl exec -it deployment/redis -n threat-intel -- redis-cli ping
```

#### 3. Application Startup Issues
```bash
# Check application status
kubectl get pods -n threat-intel

# Check application logs
kubectl logs deployment/backend -n threat-intel

# Check resource usage
kubectl top pods -n threat-intel
```

#### 4. Network Issues
```bash
# Check services
kubectl get services -n threat-intel

# Test service connectivity
kubectl exec -it deployment/backend -n threat-intel -- curl http://postgres:5432
kubectl exec -it deployment/backend -n threat-intel -- curl http://redis:6379
```

### Performance Issues

#### 1. High CPU Usage
- Check application logs for inefficient queries
- Monitor database performance
- Consider scaling up resources

#### 2. High Memory Usage
- Check for memory leaks
- Optimize application code
- Increase memory limits

#### 3. Slow Response Times
- Check database query performance
- Monitor network latency
- Review caching strategies

### Recovery Procedures

#### 1. Application Crash
```bash
# Restart application
kubectl rollout restart deployment/backend -n threat-intel
kubectl rollout restart deployment/frontend -n threat-intel

# Check status
kubectl rollout status deployment/backend -n threat-intel
```

#### 2. Database Issues
```bash
# Restart database
kubectl rollout restart statefulset/postgres -n threat-intel

# Check data integrity
kubectl exec -it postgres-0 -n threat-intel -- pg_check
```

#### 3. Complete System Recovery
```bash
# Restore from backup
kubectl exec -it postgres-0 -n threat-intel -- pg_restore -d threat_intel backup.sql

# Restart all services
kubectl rollout restart deployment/backend -n threat-intel
kubectl rollout restart deployment/frontend -n threat-intel
```

## 📞 Support

For additional support:
- Check the [main README](../README.md)
- Review the [troubleshooting guide](TROUBLESHOOTING.md)
- Create an issue in the GitHub repository
- Contact the development team

---

**Note**: Always test deployment procedures in a staging environment before applying to production. Keep backups and have a rollback plan ready. 
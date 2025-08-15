# Troubleshooting Guide

This guide provides solutions for common issues encountered when deploying and running the AI Threat Intelligence & Incident Response Platform.

## 📋 Table of Contents

1. [Quick Diagnosis](#quick-diagnosis)
2. [Common Issues](#common-issues)
3. [Performance Issues](#performance-issues)
4. [Security Issues](#security-issues)
5. [Database Issues](#database-issues)
6. [Network Issues](#network-issues)
7. [Deployment Issues](#deployment-issues)
8. [Testing Issues](#testing-issues)
9. [Recovery Procedures](#recovery-procedures)

## 🔍 Quick Diagnosis

### Health Check Commands
```bash
# Check if all services are running
docker-compose ps
kubectl get pods -n threat-intel

# Check application health
curl http://localhost:8000/health
curl http://localhost:3000

# Check database connectivity
curl http://localhost:8000/health/db

# Check Redis connectivity
curl http://localhost:8000/health/redis

# Check system resources
docker stats
kubectl top pods -n threat-intel
```

### Log Analysis
```bash
# View application logs
docker-compose logs backend
kubectl logs deployment/backend -n threat-intel

# View frontend logs
docker-compose logs frontend
kubectl logs deployment/frontend -n threat-intel

# View database logs
docker-compose logs postgres
kubectl logs statefulset/postgres -n threat-intel

# Follow logs in real-time
docker-compose logs -f
kubectl logs -f deployment/backend -n threat-intel
```

## 🚨 Common Issues

### Issue 1: Application Won't Start

**Symptoms:**
- Application fails to start
- Error messages in logs
- Port already in use

**Solutions:**

#### Docker Environment
```bash
# Check if ports are already in use
netstat -tulpn | grep :8000
netstat -tulpn | grep :3000

# Kill processes using the ports
sudo lsof -ti:8000 | xargs kill -9
sudo lsof -ti:3000 | xargs kill -9

# Restart Docker services
docker-compose down
docker-compose up -d

# Check service status
docker-compose ps
```

#### Kubernetes Environment
```bash
# Check pod status
kubectl get pods -n threat-intel

# Check pod events
kubectl describe pod <pod-name> -n threat-intel

# Check pod logs
kubectl logs <pod-name> -n threat-intel

# Restart deployment
kubectl rollout restart deployment/backend -n threat-intel
kubectl rollout restart deployment/frontend -n threat-intel
```

#### Local Environment
```bash
# Check if Python/Node processes are running
ps aux | grep python
ps aux | grep node

# Kill existing processes
pkill -f uvicorn
pkill -f "npm start"

# Restart services
cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
cd frontend && npm start
```

### Issue 2: Database Connection Failed

**Symptoms:**
- Database connection errors
- Migration failures
- Application startup failures

**Solutions:**

#### Check Database Status
```bash
# Docker
docker-compose exec postgres psql -U postgres -d threat_intel -c "SELECT version();"

# Kubernetes
kubectl exec -it postgres-0 -n threat-intel -- psql -U postgres -d threat_intel -c "SELECT version();"

# Local
sudo systemctl status postgresql
sudo -u postgres psql -c "SELECT version();"
```

#### Fix Database Issues
```bash
# Reset database (Docker)
docker-compose down -v
docker-compose up -d postgres
sleep 10
docker-compose exec postgres psql -U postgres -c "CREATE DATABASE threat_intel;"
docker-compose up -d

# Reset database (Kubernetes)
kubectl delete pvc postgres-storage-postgres-0 -n threat-intel
kubectl apply -f infrastructure/kubernetes/postgres.yaml

# Reset database (Local)
sudo -u postgres dropdb threat_intel
sudo -u postgres createdb threat_intel
alembic upgrade head
```

#### Check Environment Variables
```bash
# Verify database URL
echo $DATABASE_URL

# Test connection
python -c "
import psycopg2
try:
    conn = psycopg2.connect('$DATABASE_URL')
    print('Database connection successful')
    conn.close()
except Exception as e:
    print(f'Database connection failed: {e}')
"
```

### Issue 3: Frontend Can't Connect to Backend

**Symptoms:**
- Frontend shows connection errors
- API calls fail
- CORS errors

**Solutions:**

#### Check API URL Configuration
```bash
# Verify frontend environment variables
echo $REACT_APP_API_URL

# Test backend connectivity
curl http://localhost:8000/health
curl http://localhost:8000/docs

# Check CORS configuration
curl -H "Origin: http://localhost:3000" \
     -H "Access-Control-Request-Method: GET" \
     -H "Access-Control-Request-Headers: X-Requested-With" \
     -X OPTIONS http://localhost:8000/health
```

#### Fix CORS Issues
```python
# In backend/app/main.py, ensure CORS is properly configured
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://your-domain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

#### Check Network Connectivity
```bash
# Test network connectivity between containers
docker-compose exec backend ping frontend
docker-compose exec frontend ping backend

# Test service discovery
docker-compose exec backend nslookup frontend
docker-compose exec backend nslookup backend
```

## ⚡ Performance Issues

### Issue 1: Slow Response Times

**Symptoms:**
- API calls take too long
- Dashboard loads slowly
- Timeout errors

**Solutions:**

#### Check Database Performance
```bash
# Check slow queries
docker-compose exec postgres psql -U postgres -d threat_intel -c "
SELECT query, mean_time, calls, total_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;
"

# Check database connections
docker-compose exec postgres psql -U postgres -d threat_intel -c "
SELECT count(*) as active_connections
FROM pg_stat_activity
WHERE state = 'active';
"

# Check table sizes
docker-compose exec postgres psql -U postgres -d threat_intel -c "
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"
```

#### Optimize Database
```sql
-- Create indexes for frequently queried columns
CREATE INDEX idx_cves_severity ON cves(severity);
CREATE INDEX idx_cves_published_date ON cves(published_date);
CREATE INDEX idx_threats_category ON threats(category);

-- Analyze table statistics
ANALYZE cves;
ANALYZE threats;
ANALYZE assets;
```

#### Check Application Performance
```bash
# Monitor CPU and memory usage
docker stats
kubectl top pods -n threat-intel

# Check application logs for slow operations
docker-compose logs backend | grep -i "slow\|timeout\|error"

# Run performance tests
cd scripts
./run_stress_test.sh baseline
```

### Issue 2: High Memory Usage

**Symptoms:**
- Out of memory errors
- Application crashes
- Slow performance

**Solutions:**

#### Check Memory Usage
```bash
# Check container memory usage
docker stats --no-stream

# Check Kubernetes pod memory
kubectl top pods -n threat-intel

# Check system memory
free -h
top
```

#### Optimize Memory Usage
```python
# In backend/app/main.py, add memory monitoring
import psutil
import gc

@app.middleware("http")
async def memory_monitor(request: Request, call_next):
    process = psutil.Process()
    memory_before = process.memory_info().rss / 1024 / 1024  # MB
    
    response = await call_next(request)
    
    memory_after = process.memory_info().rss / 1024 / 1024  # MB
    if memory_after - memory_before > 100:  # 100MB threshold
        gc.collect()
    
    return response
```

#### Increase Memory Limits
```yaml
# In docker-compose.yml
services:
  backend:
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G

# In Kubernetes manifests
resources:
  requests:
    memory: "1Gi"
  limits:
    memory: "2Gi"
```

### Issue 3: High CPU Usage

**Symptoms:**
- System becomes unresponsive
- Slow application performance
- High energy consumption

**Solutions:**

#### Identify CPU-Intensive Processes
```bash
# Check CPU usage by process
top -p $(pgrep -d',' -f "uvicorn\|node")

# Check container CPU usage
docker stats --no-stream

# Check Kubernetes pod CPU
kubectl top pods -n threat-intel
```

#### Optimize CPU Usage
```python
# Use async operations where possible
import asyncio
import aiohttp

async def fetch_data_async(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [session.get(url) for url in urls]
        responses = await asyncio.gather(*tasks)
        return responses

# Use connection pooling
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True
)
```

## 🔒 Security Issues

### Issue 1: Authentication Failures

**Symptoms:**
- Login failures
- JWT token errors
- Unauthorized access

**Solutions:**

#### Check JWT Configuration
```bash
# Verify JWT secret is set
echo $JWT_SECRET_KEY

# Check JWT token format
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8000/api/v1/users/me
```

#### Fix JWT Issues
```python
# Ensure JWT secret is properly configured
from datetime import datetime, timedelta
import jwt

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY environment variable is not set")

# Create token with proper expiration
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt
```

### Issue 2: CORS Errors

**Symptoms:**
- Browser console shows CORS errors
- Frontend can't make API calls
- Preflight request failures

**Solutions:**

#### Fix CORS Configuration
```python
# Update CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://your-production-domain.com"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
```

#### Test CORS
```bash
# Test CORS preflight request
curl -X OPTIONS \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  http://localhost:8000/api/v1/auth/login
```

### Issue 3: API Key Issues

**Symptoms:**
- External API calls fail
- Rate limiting errors
- Authentication errors with external services

**Solutions:**

#### Check API Keys
```bash
# Verify API keys are set
echo $CVE_API_KEY
echo $THREAT_FEED_API_KEY

# Test API key validity
curl -H "Authorization: Bearer $CVE_API_KEY" \
     https://api.example.com/v1/cves
```

#### Fix API Key Issues
```python
# Add API key validation
import os
from typing import Optional

def validate_api_key(api_key: str, service_name: str) -> bool:
    if not api_key:
        logger.error(f"{service_name} API key is not configured")
        return False
    
    # Test API key with a simple request
    try:
        response = requests.get(
            f"https://api.{service_name}.com/health",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10
        )
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Failed to validate {service_name} API key: {e}")
        return False
```

## 🗄️ Database Issues

### Issue 1: Connection Pool Exhaustion

**Symptoms:**
- Database connection errors
- Application timeouts
- High connection count

**Solutions:**

#### Check Connection Pool
```bash
# Check active connections
docker-compose exec postgres psql -U postgres -d threat_intel -c "
SELECT count(*) as active_connections,
       count(*) FILTER (WHERE state = 'idle') as idle_connections,
       count(*) FILTER (WHERE state = 'active') as active_connections
FROM pg_stat_activity
WHERE datname = 'threat_intel';
"
```

#### Optimize Connection Pool
```python
# Update database configuration
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,  # Increase pool size
    max_overflow=30,  # Increase max overflow
    pool_pre_ping=True,  # Enable connection health checks
    pool_recycle=3600,  # Recycle connections every hour
)
```

### Issue 2: Database Lock Issues

**Symptoms:**
- Database queries hang
- Deadlock errors
- Application timeouts

**Solutions:**

#### Check for Locks
```bash
# Check for active locks
docker-compose exec postgres psql -U postgres -d threat_intel -c "
SELECT l.pid, l.mode, l.granted, a.usename, a.query
FROM pg_locks l
JOIN pg_stat_activity a ON l.pid = a.pid
WHERE NOT l.granted;
"
```

#### Fix Lock Issues
```sql
-- Kill blocking queries (use with caution)
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'active'
AND pid != pg_backend_pid()
AND query LIKE '%your_problematic_query%';

-- Cancel long-running queries
SELECT pg_cancel_backend(pid)
FROM pg_stat_activity
WHERE state = 'active'
AND now() - query_start > interval '5 minutes';
```

### Issue 3: Database Performance Issues

**Symptoms:**
- Slow queries
- High I/O wait
- Database timeouts

**Solutions:**

#### Analyze Query Performance
```bash
# Enable query logging
docker-compose exec postgres psql -U postgres -d threat_intel -c "
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_min_duration_statement = 1000;
SELECT pg_reload_conf();
"
```

#### Optimize Queries
```sql
-- Create indexes for slow queries
CREATE INDEX CONCURRENTLY idx_cves_severity_cvss ON cves(severity, cvss_score);
CREATE INDEX CONCURRENTLY idx_threats_timestamp ON threats(timestamp);
CREATE INDEX CONCURRENTLY idx_assets_organization ON assets(organization_id);

-- Update table statistics
ANALYZE cves;
ANALYZE threats;
ANALYZE assets;
ANALYZE incidents;
```

## 🌐 Network Issues

### Issue 1: Service Discovery Problems

**Symptoms:**
- Services can't find each other
- DNS resolution failures
- Network timeouts

**Solutions:**

#### Check Network Configuration
```bash
# Check Docker network
docker network ls
docker network inspect threat_intel_network

# Check Kubernetes services
kubectl get services -n threat-intel
kubectl describe service backend-service -n threat-intel

# Test DNS resolution
docker-compose exec backend nslookup frontend
docker-compose exec backend nslookup postgres
```

#### Fix Network Issues
```bash
# Recreate Docker network
docker-compose down
docker network prune
docker-compose up -d

# Restart Kubernetes services
kubectl rollout restart deployment/backend -n threat-intel
kubectl rollout restart deployment/frontend -n threat-intel
```

### Issue 2: Port Conflicts

**Symptoms:**
- Services can't bind to ports
- Port already in use errors
- Connection refused errors

**Solutions:**

#### Check Port Usage
```bash
# Check what's using the ports
sudo lsof -i :8000
sudo lsof -i :3000
sudo lsof -i :5432
sudo lsof -i :6379

# Kill processes using ports
sudo lsof -ti:8000 | xargs kill -9
sudo lsof -ti:3000 | xargs kill -9
```

#### Change Ports
```yaml
# In docker-compose.yml
services:
  backend:
    ports:
      - "8001:8000"  # Change external port
  
  frontend:
    ports:
      - "3001:3000"  # Change external port
```

## 🚀 Deployment Issues

### Issue 1: Docker Build Failures

**Symptoms:**
- Docker build errors
- Image build timeouts
- Dependency installation failures

**Solutions:**

#### Fix Docker Build Issues
```dockerfile
# Optimize Dockerfile
FROM python:3.11-slim

# Install system dependencies first
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Use multi-stage build for frontend
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
```

#### Check Build Context
```bash
# Check Docker build context
docker build --no-cache -t threat-intel-backend ./backend

# Check for large files in build context
find . -type f -size +10M

# Use .dockerignore to exclude unnecessary files
echo "node_modules" >> .dockerignore
echo "*.log" >> .dockerignore
echo ".git" >> .dockerignore
```

### Issue 2: Kubernetes Deployment Failures

**Symptoms:**
- Pods stuck in pending state
- Image pull errors
- Resource allocation failures

**Solutions:**

#### Check Pod Status
```bash
# Check pod status
kubectl get pods -n threat-intel

# Check pod events
kubectl describe pod <pod-name> -n threat-intel

# Check pod logs
kubectl logs <pod-name> -n threat-intel
```

#### Fix Deployment Issues
```bash
# Check resource availability
kubectl describe nodes

# Check image pull secrets
kubectl get secrets -n threat-intel

# Restart deployment
kubectl rollout restart deployment/backend -n threat-intel
kubectl rollout status deployment/backend -n threat-intel
```

## 🧪 Testing Issues

### Issue 1: Stress Test Failures

**Symptoms:**
- Stress tests fail
- Performance degradation
- System crashes during testing

**Solutions:**

#### Check System Resources
```bash
# Monitor system during stress test
python3 scripts/monitor_system_performance.py --duration 3600 --summary

# Check available resources
free -h
df -h
nproc
```

#### Optimize Stress Test Configuration
```bash
# Reduce load for testing
TOTAL_CVES=1000 BATCH_SIZE=50 CONCURRENT_REQUESTS=5 ./run_stress_test.sh custom

# Monitor specific components
docker stats --no-stream
kubectl top pods -n threat-intel
```

### Issue 2: Test Environment Issues

**Symptoms:**
- Tests fail in CI/CD
- Environment-specific failures
- Configuration issues

**Solutions:**

#### Check Test Environment
```bash
# Verify test environment
python3 -c "import aiohttp, psutil; print('Dependencies OK')"

# Check API availability
curl http://localhost:8000/health

# Run tests with verbose output
./run_stress_test.sh baseline --verbose
```

## 🔄 Recovery Procedures

### Complete System Reset

#### Docker Environment
```bash
# Complete reset
docker-compose down -v
docker system prune -a
docker volume prune
docker-compose up -d

# Verify services
docker-compose ps
curl http://localhost:8000/health
curl http://localhost:3000
```

#### Kubernetes Environment
```bash
# Delete and recreate namespace
kubectl delete namespace threat-intel
kubectl create namespace threat-intel

# Reapply all manifests
kubectl apply -f infrastructure/kubernetes/

# Verify deployment
kubectl get pods -n threat-intel
kubectl get services -n threat-intel
```

### Database Recovery

#### Backup and Restore
```bash
# Create backup
docker-compose exec postgres pg_dump -U postgres threat_intel > backup.sql

# Restore from backup
docker-compose exec -T postgres psql -U postgres threat_intel < backup.sql

# For Kubernetes
kubectl exec -i postgres-0 -n threat-intel -- pg_dump -U postgres threat_intel > backup.sql
kubectl exec -i postgres-0 -n threat-intel -- psql -U postgres threat_intel < backup.sql
```

### Application Recovery

#### Rollback Deployment
```bash
# Docker
docker-compose down
docker-compose up -d

# Kubernetes
kubectl rollout undo deployment/backend -n threat-intel
kubectl rollout undo deployment/frontend -n threat-intel
kubectl rollout status deployment/backend -n threat-intel
```

## 📞 Getting Help

### Diagnostic Information
When reporting issues, include:

1. **Environment Details:**
   ```bash
   # System information
   uname -a
   docker --version
   kubectl version
   python --version
   node --version
   ```

2. **Application Logs:**
   ```bash
   # Collect logs
   docker-compose logs > logs.txt
   kubectl logs deployment/backend -n threat-intel > backend-logs.txt
   kubectl logs deployment/frontend -n threat-intel > frontend-logs.txt
   ```

3. **Configuration Files:**
   - Environment variables (without sensitive data)
   - Docker Compose file
   - Kubernetes manifests

4. **Error Messages:**
   - Exact error messages
   - Stack traces
   - Screenshots (for UI issues)

### Support Channels
- **GitHub Issues**: Create detailed issue reports
- **Documentation**: Check the main README and deployment guide
- **Community**: Use GitHub Discussions
- **Email**: Contact the development team

---

**Note**: Always test recovery procedures in a staging environment before applying to production. Keep regular backups and maintain a disaster recovery plan. 
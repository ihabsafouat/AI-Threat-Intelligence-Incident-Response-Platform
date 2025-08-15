# API Logging System

This document describes the comprehensive API logging system implemented for the Threat Intelligence Platform, which logs all API requests and responses to both CloudWatch and a database.

## Overview

The API logging system provides:

- **Complete Request/Response Logging**: All API requests and responses are logged with full context
- **Dual Storage**: Logs are stored in both CloudWatch (for AWS integration) and database (for querying)
- **Performance Monitoring**: Response times and performance metrics are tracked
- **Error Tracking**: All errors are logged with stack traces and context
- **Security**: Sensitive data is automatically redacted
- **Analytics**: Built-in metrics and analytics for API usage
- **Compliance**: Audit trail for security and compliance requirements

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI App   │    │  Logging        │    │   CloudWatch    │
│                 │    │  Middleware     │    │                 │
│  - Request      │───▶│  - Extract      │───▶│  - Log Groups   │
│  - Response     │    │  - Sanitize     │    │  - Log Streams  │
│  - Error        │    │  - Log          │    │  - Metrics      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   Database      │
                       │                 │
                       │  - API Logs     │
                       │  - Metrics      │
                       │  - Alerts       │
                       └─────────────────┘
```

## Components

### 1. Logging Middleware

The system uses three middleware components:

- **LoggingMiddleware**: Main middleware that logs requests, responses, and errors
- **RequestIDMiddleware**: Adds unique request IDs to all requests
- **PerformanceMiddleware**: Tracks performance metrics and slow requests

### 2. Core Logging System

- **APILogger**: Centralized logging service that handles both CloudWatch and database logging
- **CloudWatchService**: Enhanced with API-specific logging methods
- **APILoggingService**: Database service for storing and retrieving logs

### 3. Database Models

- **APILog**: Stores individual request/response/error logs
- **APIMetrics**: Stores aggregated metrics for analytics
- **APIPerformanceAlert**: Stores performance alerts

## Configuration

### Environment Variables

```bash
# AWS Configuration (for CloudWatch logging)
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"

# Logging Configuration
export ENABLE_CLOUDWATCH_LOGGING=true
export ENABLE_DATABASE_LOGGING=true
export LOG_SENSITIVE_DATA=false
export LOG_LEVEL="INFO"
export LOG_RETENTION_DAYS=30

# API Logging Configuration
export API_LOG_REQUESTS=true
export API_LOG_RESPONSES=true
export API_LOG_ERRORS=true
export API_LOG_PERFORMANCE=true
export API_LOG_SLOW_REQUEST_THRESHOLD_MS=1000.0
```

### Settings Configuration

```python
# In app/core/config.py
class Settings(BaseSettings):
    # Logging Configuration
    ENABLE_CLOUDWATCH_LOGGING: bool = True
    ENABLE_DATABASE_LOGGING: bool = True
    LOG_SENSITIVE_DATA: bool = False
    LOG_LEVEL: str = "INFO"
    LOG_RETENTION_DAYS: int = 30
    
    # API Logging Configuration
    API_LOG_REQUESTS: bool = True
    API_LOG_RESPONSES: bool = True
    API_LOG_ERRORS: bool = True
    API_LOG_PERFORMANCE: bool = True
    API_LOG_SLOW_REQUEST_THRESHOLD_MS: float = 1000.0
```

## Logged Data

### Request Data

```json
{
  "request_id": "uuid",
  "method": "POST",
  "path": "/api/v1/threats",
  "query_params": {"limit": "10"},
  "headers": {
    "content-type": "application/json",
    "authorization": "***REDACTED***"
  },
  "body": {
    "threat_type": "malware",
    "severity": "high"
  },
  "client_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "content_length": "150"
}
```

### Response Data

```json
{
  "request_id": "uuid",
  "status_code": 201,
  "headers": {
    "content-type": "application/json"
  },
  "body": {
    "success": true,
    "threat_id": "THREAT-001"
  },
  "duration_ms": 245.67,
  "content_length": "89"
}
```

### Error Data

```json
{
  "request_id": "uuid",
  "error_type": "ValidationError",
  "error_message": "Invalid threat data",
  "stack_trace": "Traceback...",
  "request_data": {...}
}
```

## API Endpoints

### View API Logs

```http
GET /api/v1/logs/api-logs?method=POST&status_code=200&limit=50
```

**Query Parameters:**
- `request_id`: Filter by request ID
- `method`: Filter by HTTP method
- `path`: Filter by request path
- `status_code`: Filter by status code
- `user_id`: Filter by user ID
- `organization_id`: Filter by organization ID
- `client_ip`: Filter by client IP
- `event_type`: Filter by event type (request, response, error)
- `start_time`: Start time (ISO format)
- `end_time`: End time (ISO format)
- `limit`: Maximum number of results (1-1000)
- `offset`: Offset for pagination

### View API Metrics

```http
GET /api/v1/logs/api-metrics?metric_name=api_requests&time_bucket=hour
```

**Query Parameters:**
- `metric_name`: Filter by metric name
- `method`: Filter by HTTP method
- `path`: Filter by request path
- `time_bucket`: Time bucket (minute, hour, day)
- `start_time`: Start time (ISO format)
- `end_time`: End time (ISO format)
- `limit`: Maximum number of results

### Get API Logs Summary

```http
GET /api/v1/logs/api-logs/summary?hours=24
```

**Query Parameters:**
- `hours`: Hours to look back (1-168)

### Clean Up Old Logs

```http
DELETE /api/v1/logs/api-logs/cleanup?days_to_keep=30
```

**Query Parameters:**
- `days_to_keep`: Number of days to keep logs (1-365)

### Get Request Logs

```http
GET /api/v1/logs/api-logs/request/{request_id}
```

## CloudWatch Integration

### Log Groups

The system creates the following CloudWatch log groups:

- `/aws/threat-intelligence/api-logs` - Main API logs
- `/aws/threat-intelligence/platform-logs` - Application logs

### Log Streams

Log streams are created with the following naming convention:

- `api-requests-YYYY-MM-DD` - Daily API request logs
- `api-errors-YYYY-MM-DD` - Daily API error logs

### Metrics

The following CloudWatch metrics are published:

- `api_requests` - Number of API requests
- `api_responses` - Number of API responses
- `api_errors` - Number of API errors
- `api_duration` - Response time in milliseconds

**Dimensions:**
- Method (GET, POST, PUT, DELETE)
- Path (request path)
- StatusCode (HTTP status code)
- ErrorType (type of error)

## Database Schema

### APILog Table

```sql
CREATE TABLE api_logs (
    id SERIAL PRIMARY KEY,
    request_id VARCHAR(36) NOT NULL,
    session_id VARCHAR(36),
    method VARCHAR(10) NOT NULL,
    path VARCHAR(500) NOT NULL,
    query_params JSONB,
    request_headers JSONB,
    request_body TEXT,
    status_code INTEGER,
    response_headers JSONB,
    response_body TEXT,
    duration_ms FLOAT,
    request_size_bytes INTEGER,
    response_size_bytes INTEGER,
    client_ip VARCHAR(45),
    user_agent VARCHAR(500),
    referer VARCHAR(500),
    user_id VARCHAR(36),
    organization_id VARCHAR(36),
    api_key_id VARCHAR(36),
    error_type VARCHAR(100),
    error_message TEXT,
    stack_trace TEXT,
    event_type VARCHAR(20) NOT NULL,
    request_hash VARCHAR(32),
    tags JSONB,
    environment VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);
```

### APIMetrics Table

```sql
CREATE TABLE api_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value FLOAT NOT NULL,
    metric_unit VARCHAR(20) NOT NULL,
    method VARCHAR(10),
    path VARCHAR(500),
    status_code INTEGER,
    error_type VARCHAR(100),
    user_id VARCHAR(36),
    organization_id VARCHAR(36),
    client_ip VARCHAR(45),
    time_bucket VARCHAR(20) NOT NULL,
    time_period TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);
```

## Security Features

### Data Sanitization

The system automatically redacts sensitive data:

- **Headers**: `authorization`, `cookie`, `x-api-key`
- **Body Fields**: `password`, `token`, `secret`, `key`, `api_key`, `access_token`, `refresh_token`, `private_key`

### Access Control

- All log endpoints require authentication
- User context is logged for audit trails
- Organization-based filtering is supported

### Privacy Compliance

- GDPR-compliant data handling
- Configurable data retention periods
- Automatic cleanup of old logs

## Performance Considerations

### Database Optimization

- Indexes on frequently queried columns
- Partitioning by date for large datasets
- Efficient query patterns for analytics

### CloudWatch Optimization

- Batch logging to reduce API calls
- Efficient log stream management
- Metric aggregation for cost optimization

### Memory Usage

- Streaming response handling
- Configurable log limits
- Efficient data serialization

## Monitoring and Alerting

### Built-in Alerts

- Slow request detection (>1 second by default)
- High error rate alerts
- Database connection issues
- CloudWatch logging failures

### Custom Alerts

You can create custom CloudWatch alarms based on:

- API error rate > 5%
- Average response time > 500ms
- Request volume spikes
- Specific error types

## Usage Examples

### Python Client

```python
import requests

# Get API logs
response = requests.get(
    "http://localhost:8000/api/v1/logs/api-logs",
    params={
        "method": "POST",
        "status_code": 200,
        "limit": 50
    },
    headers={"Authorization": "Bearer your-token"}
)

logs = response.json()["data"]

# Get metrics
response = requests.get(
    "http://localhost:8000/api/v1/logs/api-metrics",
    params={
        "metric_name": "api_requests",
        "time_bucket": "hour"
    },
    headers={"Authorization": "Bearer your-token"}
)

metrics = response.json()["data"]
```

### cURL Examples

```bash
# Get API logs
curl -X GET "http://localhost:8000/api/v1/logs/api-logs?method=POST&limit=10" \
  -H "Authorization: Bearer your-token"

# Get summary
curl -X GET "http://localhost:8000/api/v1/logs/api-logs/summary?hours=24" \
  -H "Authorization: Bearer your-token"

# Clean up old logs
curl -X DELETE "http://localhost:8000/api/v1/logs/api-logs/cleanup?days_to_keep=30" \
  -H "Authorization: Bearer your-token"
```

## Troubleshooting

### Common Issues

1. **CloudWatch Logging Fails**
   - Check AWS credentials
   - Verify IAM permissions
   - Check network connectivity

2. **Database Logging Fails**
   - Check database connection
   - Verify table exists
   - Check database permissions

3. **High Memory Usage**
   - Reduce log retention period
   - Enable log cleanup
   - Optimize query patterns

4. **Slow Performance**
   - Add database indexes
   - Enable query caching
   - Optimize log queries

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Health Checks

Check logging system health:

```http
GET /health
```

Response includes logging service status.

## Best Practices

### 1. Log Management

- Set appropriate retention periods
- Regular cleanup of old logs
- Monitor log storage usage
- Use log rotation for large datasets

### 2. Performance

- Use pagination for large result sets
- Implement efficient filtering
- Cache frequently accessed data
- Monitor query performance

### 3. Security

- Regularly review access logs
- Monitor for suspicious activity
- Implement rate limiting
- Use secure authentication

### 4. Compliance

- Maintain audit trails
- Implement data retention policies
- Regular compliance reviews
- Document logging procedures

## Future Enhancements

### Planned Features

1. **Real-time Analytics Dashboard**
2. **Advanced Alerting Rules**
3. **Log Export Functionality**
4. **Integration with SIEM Systems**
5. **Machine Learning Anomaly Detection**

### Integration Opportunities

1. **Splunk Integration**
2. **ELK Stack Integration**
3. **Grafana Dashboards**
4. **PagerDuty Alerts**
5. **Slack Notifications**

## Support

For questions or issues with the API logging system:

1. Check the troubleshooting section above
2. Review application logs for errors
3. Verify configuration settings
4. Contact the development team with specific error messages 
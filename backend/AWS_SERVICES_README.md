# AWS Services Integration for Threat Intelligence Platform

This document describes the AWS services integration for the Threat Intelligence Platform, providing comprehensive cloud-based threat data storage, processing, monitoring, and notification capabilities.

## Overview

The AWS services integration consists of five main service modules:

1. **S3Service** - File storage and management for threat intelligence data
2. **DynamoDBService** - NoSQL database for threat records and queries
3. **CloudWatchService** - Monitoring, logging, and metrics
4. **SESService** - Email notifications and alerts
5. **LambdaService** - Serverless function integration for threat processing

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Threat Data   │───▶│   S3 Storage    │    │  DynamoDB       │
│   Sources       │    │   (Raw Data)    │    │  (Metadata)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CloudWatch    │◀───│   Lambda        │    │   SES           │
│   (Monitoring)  │    │   (Processing)  │    │   (Alerts)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Services

### 1. S3Service

**Purpose**: Store and manage threat intelligence files in Amazon S3.

**Key Features**:
- Upload threat data with compression and encryption
- Versioned storage with timestamps
- Metadata tracking and content hashing
- Presigned URL generation for secure access
- Organized folder structure by threat type

**Example Usage**:
```python
from app.services.aws import AWSConfig, S3Service

config = AWSConfig.from_env()
s3_service = S3Service(config, bucket_name="threat-intelligence-bucket")

# Upload threat data
result = s3_service.upload_threat_data(
    threat_data=threat_dict,
    threat_id="THREAT-001",
    data_type="malware",
    compress=True
)

# Retrieve threat data
retrieved = s3_service.get_threat_data("THREAT-001", "malware")
```

### 2. DynamoDBService

**Purpose**: Store and query threat intelligence records in DynamoDB.

**Key Features**:
- CRUD operations for threat records
- Query by threat type and severity using GSIs
- Batch operations for bulk data
- TTL support for automatic data expiration
- Optimized for high-throughput queries

**Example Usage**:
```python
from app.services.aws import AWSConfig, DynamoDBService

config = AWSConfig.from_env()
dynamodb_service = DynamoDBService(config, table_name="threat-intelligence")

# Create threat record
result = dynamodb_service.create_threat_record(
    threat_data=threat_dict,
    threat_id="THREAT-002",
    threat_type="phishing",
    severity="medium",
    source="email_gateway"
)

# Query threats by type
query_result = dynamodb_service.query_threats_by_type("malware", limit=100)
```

### 3. CloudWatchService

**Purpose**: Monitor threat intelligence activities and log events.

**Key Features**:
- Custom metrics for threat counts and severity
- Structured logging for threat events
- Dashboard creation for visualization
- Alarm configuration for automated responses
- Performance monitoring and alerting

**Example Usage**:
```python
from app.services.aws import AWSConfig, CloudWatchService

config = AWSConfig.from_env()
cloudwatch_service = CloudWatchService(config)

# Put threat metrics
metric_result = cloudwatch_service.put_threat_metric(
    threat_type="malware",
    severity="high",
    count=5,
    source="automated_scanner"
)

# Log threat event
log_result = cloudwatch_service.log_threat_event(
    threat_id="THREAT-003",
    event_type="detection",
    description="New malware variant detected",
    severity="high"
)
```

### 4. SESService

**Purpose**: Send email notifications and alerts for threat intelligence.

**Key Features**:
- Threat alert emails with severity indicators
- Daily/weekly threat reports
- HTML and plain text email support
- Email verification and quota management
- Professional email templates

**Example Usage**:
```python
from app.services.aws import AWSConfig, SESService

config = AWSConfig.from_env()
ses_service = SESService(config, from_email="threat-intel@yourdomain.com")

# Send threat alert
alert_result = ses_service.send_threat_alert(
    to_addresses=["security-team@yourdomain.com"],
    threat_data=threat_dict,
    alert_type="critical",
    severity="critical"
)

# Send daily report
report_result = ses_service.send_daily_report(
    to_addresses=["management@yourdomain.com"],
    report_data=report_dict
)
```

### 5. LambdaService

**Purpose**: Integrate with AWS Lambda for serverless threat processing.

**Key Features**:
- Invoke threat analysis functions
- Threat enrichment and correlation
- Data processing workflows
- Alert generation automation
- Function management and monitoring

**Example Usage**:
```python
from app.services.aws import AWSConfig, LambdaService

config = AWSConfig.from_env()
lambda_service = LambdaService(config)

# Invoke threat analysis
analysis_result = lambda_service.invoke_threat_analysis(
    threat_data=threat_dict,
    analysis_type="advanced"
)

# Invoke threat enrichment
enrichment_result = lambda_service.invoke_threat_enrichment(
    threat_indicators=["malicious-ip.com", "abc123hash"],
    enrichment_sources=["virustotal", "abuseipdb"]
)
```

## Configuration

### Environment Variables

Set the following environment variables for AWS configuration:

```bash
# AWS Credentials
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"

# Service-specific configuration
export S3_BUCKET="threat-intelligence-bucket"
export DYNAMODB_TABLE="threat-intelligence"
export SES_FROM_EMAIL="threat-intel@yourdomain.com"
```

### AWS IAM Permissions

Ensure your AWS credentials have the following permissions:

**S3 Permissions**:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::threat-intelligence-bucket",
                "arn:aws:s3:::threat-intelligence-bucket/*"
            ]
        }
    ]
}
```

**DynamoDB Permissions**:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchWriteItem"
            ],
            "Resource": "arn:aws:dynamodb:*:*:table/threat-intelligence"
        }
    ]
}
```

**CloudWatch Permissions**:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "cloudwatch:PutDashboard"
            ],
            "Resource": "*"
        }
    ]
}
```

**SES Permissions**:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ses:SendEmail",
                "ses:SendRawEmail",
                "ses:VerifyEmailIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

**Lambda Permissions**:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:InvokeFunction",
                "lambda:ListFunctions",
                "lambda:GetFunction"
            ],
            "Resource": "arn:aws:lambda:*:*:function:threat-*"
        }
    ]
}
```

## Usage Examples

### Quick Start

```python
from app.services.aws import AWSConfig, ThreatIntelligenceAWS

# Initialize AWS utilities
aws_utils = ThreatIntelligenceAWS(region="us-east-1")

# Store threat data
threat_data = {
    "threat_id": "THREAT-001",
    "threat_type": "malware",
    "severity": "high",
    "description": "Advanced persistent threat detected",
    "indicators": ["192.168.1.100", "malicious-domain.com"],
    "source": "security_scanner"
}

result = aws_utils.store_threat(threat_data)
print(f"Stored threat: {result['threat_id']}")

# Search threats
search_result = aws_utils.search_threats(threat_type="malware", limit=10)
print(f"Found {search_result['count']} malware threats")

# Send alert
alert_result = aws_utils.send_alert(
    threat_data, 
    ["security-team@yourdomain.com"]
)
print(f"Alert sent: {alert_result['message_id']}")
```

### Command Line Interface

Use the utility script for quick operations:

```bash
# Store threat from JSON file
python scripts/aws_utils.py --action store --file threat_data.json

# Search threats by type
python scripts/aws_utils.py --action search --threat-type malware --limit 20

# Get specific threat
python scripts/aws_utils.py --action get --threat-id THREAT-001

# Send alert
python scripts/aws_utils.py --action alert --file threat_data.json --recipients security@domain.com

# Get metrics
python scripts/aws_utils.py --action metrics --hours 48

# List S3 files
python scripts/aws_utils.py --action list-files --limit 50
```

### Integrated Workflow

```python
from app.services.aws import AWSConfig, S3Service, DynamoDBService, CloudWatchService, SESService, LambdaService

# Initialize all services
config = AWSConfig.from_env()
s3_service = S3Service(config)
dynamodb_service = DynamoDBService(config)
cloudwatch_service = CloudWatchService(config)
ses_service = SESService(config)
lambda_service = LambdaService(config)

# Complete threat processing workflow
def process_threat(threat_data):
    # 1. Store in S3
    s3_result = s3_service.upload_threat_data(threat_data, threat_data['threat_id'])
    
    # 2. Store in DynamoDB
    dynamodb_result = dynamodb_service.create_threat_record(threat_data)
    
    # 3. Send metrics
    cloudwatch_service.put_threat_metric(
        threat_data['threat_type'],
        threat_data['severity'],
        1,
        threat_data['source']
    )
    
    # 4. Log event
    cloudwatch_service.log_threat_event(
        threat_data['threat_id'],
        'detection',
        threat_data['description'],
        threat_data['severity']
    )
    
    # 5. Analyze with Lambda
    if threat_data['severity'] in ['high', 'critical']:
        lambda_service.invoke_threat_analysis(threat_data, 'advanced')
    
    # 6. Send alert
    if threat_data['severity'] == 'critical':
        ses_service.send_threat_alert(
            ['incident-response@domain.com'],
            threat_data,
            'critical'
        )
    
    return {
        's3': s3_result['success'],
        'dynamodb': dynamodb_result['success'],
        'alert_sent': threat_data['severity'] == 'critical'
    }
```

## Best Practices

### Security
1. **Encryption**: All S3 data is encrypted at rest and in transit
2. **IAM**: Use least-privilege IAM policies
3. **VPC**: Consider using VPC endpoints for private access
4. **Monitoring**: Enable CloudTrail for API call logging

### Performance
1. **Caching**: Use CloudFront for S3 content delivery
2. **Batch Operations**: Use DynamoDB batch operations for bulk data
3. **Connection Pooling**: Reuse AWS service clients
4. **Async Operations**: Use async/await for non-blocking operations

### Cost Optimization
1. **S3 Lifecycle**: Configure lifecycle policies for old data
2. **DynamoDB**: Use on-demand pricing for variable workloads
3. **CloudWatch**: Set retention policies for logs
4. **Lambda**: Optimize function memory and timeout settings

### Monitoring
1. **Metrics**: Track threat counts, processing times, and errors
2. **Alarms**: Set up alarms for critical thresholds
3. **Dashboards**: Create CloudWatch dashboards for visualization
4. **Logs**: Centralize logs for analysis and debugging

## Troubleshooting

### Common Issues

**Authentication Errors**:
```bash
# Check AWS credentials
aws sts get-caller-identity

# Verify environment variables
echo $AWS_ACCESS_KEY_ID
echo $AWS_REGION
```

**Permission Errors**:
```bash
# Test S3 access
aws s3 ls s3://your-bucket-name

# Test DynamoDB access
aws dynamodb describe-table --table-name your-table-name
```

**Service Errors**:
```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Check service status
s3_service.check_bucket_exists()
dynamodb_service.get_table_info()
```

### Error Handling

All service methods return consistent result dictionaries:

```python
{
    'success': True/False,
    'data': {...},  # Success data
    'error': 'error message'  # Error details
}
```

### Debug Mode

Enable debug mode for detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# All AWS service calls will now log detailed information
```

## Future Enhancements

### Planned Features
1. **SQS Integration**: Message queuing for async processing
2. **SNS Integration**: Push notifications for mobile alerts
3. **Athena Integration**: SQL queries on S3 data
4. **Glue Integration**: ETL workflows for data processing
5. **Step Functions**: Orchestrate complex workflows
6. **EventBridge**: Event-driven architecture
7. **API Gateway**: RESTful API endpoints
8. **Cognito**: User authentication and authorization

### Integration Opportunities
1. **Slack**: Real-time notifications
2. **Jira**: Issue tracking integration
3. **Splunk**: Log analysis and correlation
4. **Elasticsearch**: Advanced search capabilities
5. **Grafana**: Custom dashboards
6. **PagerDuty**: Incident management
7. **ServiceNow**: IT service management
8. **Microsoft Teams**: Team collaboration

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review AWS service documentation
3. Enable debug logging for detailed error information
4. Verify AWS credentials and permissions
5. Test with the provided example scripts

## License

This AWS services integration is part of the Threat Intelligence Platform and follows the same licensing terms. 
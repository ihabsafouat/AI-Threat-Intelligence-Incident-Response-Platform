# AWS S3 Storage Guide for Threat Intelligence Platform

This guide covers the comprehensive S3 storage implementation for storing raw threat intelligence data in AWS S3.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Setup Instructions](#setup-instructions)
4. [Configuration](#configuration)
5. [Usage Examples](#usage-examples)
6. [API Endpoints](#api-endpoints)
7. [Airflow Integration](#airflow-integration)
8. [Best Practices](#best-practices)
9. [Monitoring and Maintenance](#monitoring-and-maintenance)
10. [Troubleshooting](#troubleshooting)

## Overview

The S3 storage implementation provides a comprehensive solution for storing raw threat intelligence data with the following features:

- **Organized Storage**: Hierarchical folder structure for different data types
- **Data Compression**: Automatic gzip compression to reduce storage costs
- **Encryption**: Server-side encryption for data security
- **Lifecycle Policies**: Automated data lifecycle management
- **Backup and Archival**: Automated backup and archival processes
- **Data Integrity**: Hash-based data validation
- **Cost Optimization**: Storage class optimization

## Architecture

### Storage Structure

```
threat-intelligence-platform/
├── raw/                          # Raw data storage
│   ├── vulnerability/            # CVE and vulnerability data
│   │   ├── nvd/                 # NVD data
│   │   └── other_sources/       # Other vulnerability sources
│   ├── malware/                 # Malware data
│   │   ├── virustotal/          # VirusTotal data
│   │   └── other_sources/       # Other malware sources
│   └── exposure/                # Exposure data
│       ├── shodan/              # Shodan data
│       └── other_sources/       # Other exposure sources
├── processed/                    # Processed data storage
├── archive/                      # Archived data
├── backup/                       # Backup data
├── logs/                         # Application logs
└── temp/                         # Temporary files
```

### Data Flow

1. **Data Ingestion**: Raw data is extracted from various sources
2. **S3 Storage**: Raw data is stored in S3 with metadata
3. **Processing**: Data is processed and stored in processed folder
4. **Archival**: Old data is moved to archive storage
5. **Cleanup**: Very old data is deleted based on retention policies

## Setup Instructions

### 1. Prerequisites

- AWS account with appropriate permissions
- AWS CLI configured
- Python 3.11+
- Required Python packages (see requirements.txt)

### 2. AWS Configuration

#### Create S3 Bucket

```bash
# Create S3 bucket
aws s3 mb s3://threat-intelligence-platform --region us-east-1

# Enable versioning
aws s3api put-bucket-versioning \
    --bucket threat-intelligence-platform \
    --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
    --bucket threat-intelligence-platform \
    --server-side-encryption-configuration '{
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }
        ]
    }'
```

#### Configure Lifecycle Policies

```bash
# Create lifecycle policy
aws s3api put-bucket-lifecycle-configuration \
    --bucket threat-intelligence-platform \
    --lifecycle-configuration '{
        "Rules": [
            {
                "ID": "hot_data_rule",
                "Status": "Enabled",
                "Filter": {"Prefix": "raw/"},
                "Transitions": [
                    {
                        "Days": 30,
                        "StorageClass": "STANDARD_IA"
                    },
                    {
                        "Days": 90,
                        "StorageClass": "GLACIER"
                    },
                    {
                        "Days": 365,
                        "StorageClass": "DEEP_ARCHIVE"
                    }
                ]
            }
        ]
    }'
```

### 3. Environment Variables

Add the following to your `.env` file:

```bash
# AWS Configuration
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_REGION=us-east-1
S3_BUCKET=threat-intelligence-platform

# S3 Storage Configuration
S3_COMPRESSION_ENABLED=true
S3_ENCRYPTION_ENABLED=true
S3_LIFECYCLE_ENABLED=true
```

### 4. Install Dependencies

```bash
pip install boto3
pip install aioboto3  # For async operations
```

## Configuration

### S3StorageConfig

```python
from app.services.storage.s3_storage import S3StorageConfig

config = S3StorageConfig(
    bucket_name="threat-intelligence-platform",
    region="us-east-1",
    folder_structure={
        "raw_data": "raw/",
        "processed_data": "processed/",
        "archived_data": "archive/",
        "backup_data": "backup/",
        "logs": "logs/",
        "temp": "temp/"
    },
    lifecycle_policies={
        "hot_data": {"days": 30, "storage_class": "STANDARD"},
        "warm_data": {"days": 90, "storage_class": "STANDARD_IA"},
        "cold_data": {"days": 365, "storage_class": "GLACIER"},
        "archive_data": {"days": 2555, "storage_class": "DEEP_ARCHIVE"}
    },
    compression_enabled=True,
    encryption_enabled=True
)
```

## Usage Examples

### Basic Usage

```python
from app.services.storage.s3_storage import S3StorageService

# Initialize service
s3_storage = S3StorageService()

# Store raw data
file_key = await s3_storage.store_raw_data(
    data=threat_data,
    data_type="vulnerability",
    source="nvd",
    metadata={
        "api_version": "2.0",
        "extraction_date": "2024-01-15"
    }
)

# Retrieve data
data = await s3_storage.retrieve_data(file_key)

# List files
files = await s3_storage.list_data_files(
    data_type="vulnerability",
    source="nvd",
    date_range=(start_date, end_date)
)
```

### Enhanced ETL Pipeline

```python
from app.services.ingestion.enhanced_etl_pipeline import EnhancedETLPipeline

# Initialize pipeline
etl_pipeline = EnhancedETLPipeline()

# Ingest NVD data
result = await etl_pipeline.ingest_nvd_data(days=7)
print(f"Ingested {result.record_count} records")
print(f"S3 file key: {result.s3_file_key}")

# Get metrics
metrics = await etl_pipeline.get_ingestion_metrics(days=30)
print(f"Total files: {metrics['s3_storage']['total_files']}")

# Cleanup old data
cleanup_results = await etl_pipeline.cleanup_old_data(days_old=90)
print(f"Cleaned {cleanup_results['s3_files_cleaned']} files")
```

## API Endpoints

### Storage Metrics

```bash
GET /api/v1/storage/metrics?days=30
```

Response:
```json
{
    "storage": {
        "total_files": 1250,
        "total_size": 1073741824,
        "files_by_type": {
            "vulnerability": 500,
            "malware": 400,
            "exposure": 350
        },
        "files_by_source": {
            "nvd": 500,
            "virustotal": 400,
            "shodan": 350
        }
    },
    "ingestion": {
        "summary": {
            "total_files_stored": 1250,
            "total_data_size": 1073741824,
            "total_records_ingested": 50000
        }
    }
}
```

### List Files

```bash
GET /api/v1/storage/files?data_type=vulnerability&source=nvd&days=7
```

### Retrieve File

```bash
GET /api/v1/storage/files/raw/vulnerability/nvd/2024/01/15/143022_a1b2c3d4.json.gz
```

### Backup Data

```bash
POST /api/v1/storage/backup
Content-Type: application/json

{
    "file_keys": [
        "raw/vulnerability/nvd/2024/01/15/143022_a1b2c3d4.json.gz",
        "raw/malware/virustotal/2024/01/15/143023_e5f6g7h8.json.gz"
    ]
}
```

### Archive Data

```bash
POST /api/v1/storage/archive
Content-Type: application/json

{
    "file_keys": ["raw/vulnerability/nvd/2024/01/01/old_file.json.gz"],
    "archive_reason": "data_retention"
}
```

## Airflow Integration

### S3 Storage DAG

The `s3_storage_operations` DAG runs daily and performs:

1. **Health Check**: Verify S3 bucket accessibility
2. **Backup**: Create backups of critical data
3. **Archival**: Move old data to archive storage
4. **Cleanup**: Delete very old data
5. **Optimization**: Check storage cost optimization
6. **Validation**: Validate data integrity
7. **Reporting**: Generate storage reports

### Manual Triggers

```bash
# Trigger S3 storage operations
docker-compose run --rm airflow-webserver airflow dags trigger s3_storage_operations

# Trigger with custom parameters
docker-compose run --rm airflow-webserver airflow dags trigger s3_storage_operations \
    --conf '{"cleanup_days": 60, "backup_critical": true}'
```

## Best Practices

### 1. Data Organization

- Use consistent naming conventions
- Organize by data type and source
- Include timestamps in file names
- Use appropriate file extensions

### 2. Storage Optimization

- Enable compression for text data
- Use appropriate storage classes
- Implement lifecycle policies
- Monitor storage costs

### 3. Security

- Enable server-side encryption
- Use IAM roles and policies
- Implement access logging
- Regular security audits

### 4. Performance

- Use async operations
- Implement retry logic
- Batch operations when possible
- Monitor performance metrics

### 5. Data Management

- Regular backups
- Automated archival
- Data integrity checks
- Retention policy enforcement

## Monitoring and Maintenance

### Storage Metrics

Monitor the following metrics:

- **Storage Usage**: Total files and size
- **Cost**: Storage and transfer costs
- **Performance**: Upload/download times
- **Errors**: Failed operations
- **Lifecycle**: Transition events

### Health Checks

```python
# Check S3 health
GET /api/v1/storage/health

# Response
{
    "status": "healthy",
    "s3_operations": {
        "store": "success",
        "retrieve": "success",
        "cleanup": "success"
    },
    "test_data": {...},
    "timestamp": "2024-01-15T14:30:22Z"
}
```

### Automated Maintenance

The system includes automated maintenance tasks:

- **Daily**: Health checks, backups, archival
- **Weekly**: Storage optimization, cost analysis
- **Monthly**: Data integrity validation, cleanup

## Troubleshooting

### Common Issues

#### 1. S3 Bucket Not Found

```python
# Error: NoSuchBucket
# Solution: Create bucket or check bucket name
s3_storage = S3StorageService(config=S3StorageConfig(
    bucket_name="correct-bucket-name"
))
```

#### 2. Permission Denied

```python
# Error: AccessDenied
# Solution: Check IAM permissions
# Required permissions:
# - s3:GetObject
# - s3:PutObject
# - s3:DeleteObject
# - s3:ListBucket
```

#### 3. Network Issues

```python
# Error: Connection timeout
# Solution: Check network connectivity and AWS region
import boto3
boto3.setup_default_session(region_name='us-east-1')
```

#### 4. Data Corruption

```python
# Error: Invalid data format
# Solution: Validate data before storage
def validate_data(data):
    if not isinstance(data, (dict, list)):
        raise ValueError("Data must be dict or list")
    return True
```

### Debug Mode

Enable debug logging:

```python
import logging
logging.getLogger('app.services.storage.s3_storage').setLevel(logging.DEBUG)
```

### Performance Tuning

```python
# Optimize for large files
config = S3StorageConfig(
    compression_enabled=True,
    multipart_threshold=100 * 1024 * 1024,  # 100MB
    multipart_chunksize=10 * 1024 * 1024    # 10MB chunks
)
```

## Cost Optimization

### Storage Classes

- **STANDARD**: Frequently accessed data
- **STANDARD_IA**: Infrequently accessed data
- **GLACIER**: Long-term archival
- **DEEP_ARCHIVE**: Very long-term archival

### Lifecycle Policies

```python
lifecycle_policies = {
    "hot_data": {"days": 30, "storage_class": "STANDARD"},
    "warm_data": {"days": 90, "storage_class": "STANDARD_IA"},
    "cold_data": {"days": 365, "storage_class": "GLACIER"},
    "archive_data": {"days": 2555, "storage_class": "DEEP_ARCHIVE"}
}
```

### Cost Monitoring

```python
# Get cost metrics
import boto3

ce_client = boto3.client('ce')
response = ce_client.get_cost_and_usage(
    TimePeriod={
        'Start': '2024-01-01',
        'End': '2024-01-31'
    },
    Granularity='MONTHLY',
    Metrics=['UnblendedCost'],
    GroupBy=[
        {'Type': 'DIMENSION', 'Key': 'SERVICE'}
    ]
)
```

## Conclusion

The S3 storage implementation provides a robust, scalable, and cost-effective solution for storing threat intelligence data. With proper configuration and monitoring, it can handle large volumes of data while maintaining security and performance.

For additional support or questions, refer to:
- AWS S3 Documentation
- Platform logs and monitoring
- API documentation
- Airflow task logs 
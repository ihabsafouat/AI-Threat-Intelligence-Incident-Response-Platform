# KMS Encryption for S3 File Storage

This document describes the implementation of AWS Key Management Service (KMS) encryption for S3 file storage in the Threat Intelligence Platform.

## Overview

The platform now supports AWS KMS encryption for all S3 file operations, providing enhanced security through:

- **Hardware Security Module (HSM) Protection**: Keys are stored in AWS CloudHSM
- **Automatic Key Rotation**: Keys can be automatically rotated without application changes
- **Detailed Audit Logs**: All key usage is logged in CloudTrail
- **Compliance Support**: Meets various compliance requirements (SOC, PCI DSS, HIPAA, etc.)
- **Centralized Key Management**: All encryption keys are managed centrally

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │    │   S3 Service    │    │   KMS Service   │
│                 │    │                 │    │                 │
│  - Upload File  │───▶│  - Encrypt      │───▶│  - Generate     │
│  - Download     │    │  - Store        │    │    Data Key     │
│  - Retrieve     │    │  - Retrieve     │    │  - Encrypt      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   S3 Bucket     │    │   CloudTrail    │
                       │                 │    │                 │
                       │  - Encrypted    │    │  - Audit Logs   │
                       │    Files        │    │  - Key Usage    │
                       └─────────────────┘    └─────────────────┘
```

## Implementation Details

### 1. S3Service Updates

The `S3Service` class has been enhanced to support KMS encryption:

```python
class S3Service:
    def __init__(self, config: AWSConfig, bucket_name: Optional[str] = None, kms_key_id: Optional[str] = None):
        self.kms_key_id = kms_key_id or os.getenv('KMS_KEY_ID')
        # ... rest of initialization
```

**Key Features:**
- Automatic KMS key detection from environment variables
- Fallback to AES256 encryption if no KMS key is provided
- Enhanced logging of encryption type and key information
- Support for both file uploads and threat data storage

### 2. S3StorageService Updates

The `S3StorageService` class supports KMS encryption for raw data storage:

```python
class S3StorageConfig(BaseModel):
    kms_key_id: Optional[str] = None
    encryption_enabled: bool = True
```

**Key Features:**
- Configurable KMS key ID
- Automatic bucket encryption configuration
- Support for both raw and processed data encryption

### 3. New KMSService

A dedicated `KMSService` class provides comprehensive KMS operations:

```python
class KMSService:
    def create_key(self, description: str, key_usage: str = 'ENCRYPT_DECRYPT') -> Dict[str, Any]
    def describe_key(self, key_id: str) -> Dict[str, Any]
    def list_keys(self, limit: int = 100) -> Dict[str, Any]
    def encrypt_data(self, key_id: str, plaintext: bytes) -> Dict[str, Any]
    def decrypt_data(self, ciphertext: bytes, key_id: Optional[str] = None) -> Dict[str, Any]
    # ... and more
```

## Configuration

### Environment Variables

Set the following environment variables to enable KMS encryption:

```bash
# Required for KMS encryption
export KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv"

# Optional: AWS region (defaults to us-east-1)
export AWS_REGION="us-east-1"

# Required: AWS credentials
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"

# Optional: S3 bucket name
export S3_BUCKET="your-threat-intelligence-bucket"
```

### AWS IAM Permissions

The following IAM permissions are required for KMS encryption:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:CreateKey",
                "kms:CreateAlias",
                "kms:DescribeKey",
                "kms:ListKeys",
                "kms:ListAliases",
                "kms:EnableKey",
                "kms:DisableKey",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion",
                "kms:GetKeyPolicy",
                "kms:PutKeyPolicy",
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::your-bucket-name",
                "arn:aws:s3:::your-bucket-name/*"
            ]
        }
    ]
}
```

## Usage Examples

### Basic S3 Upload with KMS Encryption

```python
from app.services.aws import AWSConfig, S3Service

# Initialize with KMS encryption
config = AWSConfig.from_env()
s3_service = S3Service(
    config, 
    bucket_name="threat-intelligence-bucket",
    kms_key_id="arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ef-ghij-klmnopqrstuv"
)

# Upload file with KMS encryption
result = s3_service.upload_file(
    file_path="/path/to/sensitive/file.json",
    s3_key="threats/encrypted-file.json",
    encrypt=True
)

print(f"Encryption: {result['encryption']}")
print(f"KMS Key ID: {result['kms_key_id']}")
```

### Threat Data Storage with KMS Encryption

```python
# Upload threat data with KMS encryption
threat_data = {
    "threat_id": "THREAT-001",
    "threat_type": "malware",
    "severity": "high",
    "indicators": ["192.168.1.100", "malicious-domain.com"]
}

result = s3_service.upload_threat_data(
    threat_data=threat_data,
    threat_id="THREAT-001",
    data_type="malware",
    compress=True
)

if result['success']:
    print(f"✅ Uploaded with {result['encryption']} encryption")
    print(f"   KMS Key: {result['kms_key_id']}")
```

### KMS Key Management

```python
from app.services.aws import KMSService

kms_service = KMSService(config)

# Create a new KMS key
key_result = kms_service.create_key(
    description="S3 encryption key for threat intelligence",
    key_usage="ENCRYPT_DECRYPT"
)

if key_result['success']:
    print(f"Created key: {key_result['key_id']}")

# List existing keys
keys_result = kms_service.list_keys()
for key in keys_result['keys']:
    print(f"Key: {key['key_id']} - {key['description']}")
```

## Security Best Practices

### 1. Key Management

- **Use Customer Managed Keys**: Create your own KMS keys instead of using AWS managed keys
- **Enable Key Rotation**: Configure automatic key rotation for enhanced security
- **Limit Key Permissions**: Use least-privilege access for key operations
- **Monitor Key Usage**: Set up CloudWatch alarms for unusual key activity

### 2. Access Control

- **IAM Roles**: Use IAM roles instead of access keys when possible
- **Conditional Policies**: Use IAM conditions to restrict key usage
- **Cross-Account Access**: Use key policies for cross-account access

### 3. Monitoring and Logging

- **CloudTrail**: Enable CloudTrail logging for all KMS operations
- **CloudWatch**: Set up metrics and alarms for key usage
- **AWS Config**: Enable AWS Config rules for KMS compliance

### 4. Data Protection

- **Encrypt at Rest**: All S3 objects are encrypted at rest
- **Encrypt in Transit**: Use HTTPS for all S3 operations
- **Key Aliases**: Use key aliases for easier key management

## Migration from AES256 to KMS

### Step 1: Create KMS Key

```python
from app.services.aws import KMSService

kms_service = KMSService(config)
key_result = kms_service.create_key(
    description="Migration key for existing S3 data",
    key_usage="ENCRYPT_DECRYPT"
)
```

### Step 2: Update Configuration

Set the `KMS_KEY_ID` environment variable:

```bash
export KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/your-new-key-id"
```

### Step 3: Re-encrypt Existing Data

```python
# Download existing files and re-upload with KMS encryption
existing_files = s3_service.list_threat_files()

for file_info in existing_files['files']:
    # Download with old encryption
    download_result = s3_service.download_file(
        s3_key=file_info['key'],
        local_path=f"/tmp/{file_info['key'].split('/')[-1]}"
    )
    
    if download_result['success']:
        # Re-upload with KMS encryption
        upload_result = s3_service.upload_file(
            file_path=download_result['local_path'],
            s3_key=file_info['key'],
            encrypt=True  # This will use KMS encryption
        )
        
        if upload_result['success']:
            print(f"✅ Re-encrypted: {file_info['key']}")
```

## Testing

### Run KMS Encryption Example

```bash
cd backend/scripts
python kms_encryption_example.py
```

This script demonstrates:
- KMS key creation and management
- S3 file encryption with KMS
- Data encryption/decryption operations
- Key listing and information retrieval

### Run AWS Examples with KMS

```bash
cd backend/scripts
python aws_examples.py
```

This includes KMS operations in the comprehensive workflow example.

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure IAM permissions include KMS operations
   - Check key policy allows your role/user

2. **Key Not Found**
   - Verify KMS key ID is correct
   - Ensure key exists in the specified region

3. **Encryption Context Mismatch**
   - KMS encryption context must match for decryption
   - Check if context is being modified

4. **Key Disabled**
   - Enable the KMS key if it's disabled
   - Check key state with `describe_key()`

### Debug Mode

Enable debug logging to troubleshoot issues:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Compliance and Auditing

### CloudTrail Logs

All KMS operations are logged in CloudTrail:

```bash
aws logs filter-log-events \
    --log-group-name CloudTrail/DefaultLogGroup \
    --filter-pattern "eventName LIKE 'KMS%'"
```

### Key Usage Metrics

Monitor key usage with CloudWatch:

```python
# Get key usage metrics
kms_service = KMSService(config)
key_info = kms_service.describe_key(kms_key_id)
print(f"Key state: {key_info['key_state']}")
```

## Performance Considerations

### Encryption Overhead

- **KMS API Calls**: Each encryption/decryption requires a KMS API call
- **Latency**: KMS operations add ~10-50ms latency
- **Throughput**: KMS has rate limits (default: 10,000 requests/second)

### Optimization Strategies

1. **Data Key Caching**: Cache data keys for multiple operations
2. **Batch Operations**: Group multiple files for batch processing
3. **Async Operations**: Use async/await for non-blocking operations

## Cost Considerations

### KMS Pricing

- **Customer Managed Keys**: $1.00 per key per month
- **API Calls**: $0.03 per 10,000 API calls
- **Data Key Requests**: $0.03 per 10,000 requests

### Cost Optimization

1. **Key Reuse**: Use the same key for multiple applications
2. **Request Batching**: Minimize API calls through batching
3. **Monitoring**: Monitor usage to identify optimization opportunities

## Future Enhancements

### Planned Features

1. **Multi-Region Keys**: Support for KMS multi-region keys
2. **Custom Key Stores**: Integration with CloudHSM custom key stores
3. **Key Rotation Automation**: Automatic key rotation workflows
4. **Encryption Context**: Enhanced encryption context support

### Integration Opportunities

1. **Secrets Manager**: Integration with AWS Secrets Manager
2. **Certificate Manager**: SSL/TLS certificate management
3. **CloudHSM**: Hardware security module integration

## Support and Resources

### Documentation

- [AWS KMS Developer Guide](https://docs.aws.amazon.com/kms/)
- [AWS S3 Encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingEncryption.html)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-learning/)

### Tools and Scripts

- `backend/scripts/kms_encryption_example.py`: Comprehensive KMS example
- `backend/scripts/aws_examples.py`: AWS services with KMS integration
- `backend/scripts/aws_utils.py`: Utility functions with KMS support

### Contact

For questions or issues with KMS encryption implementation:

1. Check the troubleshooting section above
2. Review CloudTrail logs for detailed error information
3. Contact the development team with specific error messages 
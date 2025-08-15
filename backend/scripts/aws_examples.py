#!/usr/bin/env python3
"""
AWS Services Examples

This script demonstrates how to use the AWS services for threat intelligence operations with KMS encryption.
"""

import os
import sys
import json
from datetime import datetime, timezone
from pathlib import Path

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.aws import (
    AWSConfig, S3Service, DynamoDBService, 
    CloudWatchService, SESService, LambdaService
)


def example_s3_operations():
    """Example S3 operations for threat data storage with KMS encryption."""
    print("=== S3 Operations Example with KMS Encryption ===")
    
    # Initialize AWS config and S3 service with KMS encryption
    config = AWSConfig.from_env()
    
    # Get KMS key ID from environment or use default
    kms_key_id = os.getenv('KMS_KEY_ID')
    if kms_key_id:
        print(f"Using KMS encryption with key: {kms_key_id}")
    else:
        print("No KMS key ID provided, using AES256 encryption")
    
    s3_service = S3Service(
        config, 
        bucket_name="threat-intelligence-bucket",
        kms_key_id=kms_key_id
    )
    
    # Example threat data
    threat_data = {
        "threat_id": "THREAT-001",
        "threat_type": "malware",
        "severity": "high",
        "description": "Advanced persistent threat detected",
        "indicators": ["192.168.1.100", "malicious-domain.com", "abc123def456"],
        "source": "security_scanner",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "malware_family": "TrickBot",
            "target_industry": "financial",
            "attack_vector": "phishing"
        }
    }
    
    # Upload threat data to S3 with KMS encryption
    print("Uploading threat data to S3 with KMS encryption...")
    result = s3_service.upload_threat_data(
        threat_data=threat_data,
        threat_id="THREAT-001",
        data_type="malware",
        compress=True
    )
    
    if result['success']:
        encryption_type = result.get('encryption', 'Unknown')
        kms_key_used = result.get('kms_key_id', 'None')
        print(f"✅ Successfully uploaded threat data: {result['key']}")
        print(f"   Encryption: {encryption_type}")
        print(f"   KMS Key ID: {kms_key_used}")
        
        # Retrieve the threat data
        print("Retrieving threat data from S3...")
        retrieved = s3_service.get_threat_data("THREAT-001", "malware")
        
        if retrieved['success']:
            print(f"✅ Retrieved threat data: {retrieved['threat_data']['threat_id']}")
        else:
            print(f"❌ Failed to retrieve threat data: {retrieved['error']}")
    else:
        print(f"❌ Failed to upload threat data: {result['error']}")


def example_kms_operations():
    """Example KMS operations for key management."""
    print("\n=== KMS Operations Example ===")
    
    # Initialize AWS config
    config = AWSConfig.from_env()
    
    # Get KMS key information
    kms_key_info = config.get_kms_key_info()
    if kms_key_info:
        print("✅ KMS Key Information:")
        print(f"   Key ID: {kms_key_info['key_id']}")
        print(f"   Key ARN: {kms_key_info['key_arn']}")
        print(f"   Description: {kms_key_info['description']}")
        print(f"   State: {kms_key_info['key_state']}")
        print(f"   Usage: {kms_key_info['key_usage']}")
        print(f"   Created: {kms_key_info['creation_date']}")
    else:
        print("❌ No KMS key information available")


def example_dynamodb_operations():
    """Example DynamoDB operations for threat data storage."""
    print("\n=== DynamoDB Operations Example ===")
    
    # Initialize AWS config and DynamoDB service
    config = AWSConfig.from_env()
    dynamodb_service = DynamoDBService(config, table_name="threat-intelligence")
    
    # Create table if it doesn't exist
    print("Creating DynamoDB table if it doesn't exist...")
    table_result = dynamodb_service.create_table_if_not_exists()
    print(f"Table status: {table_result['success']}")
    
    # Example threat data
    threat_data = {
        "threat_id": "THREAT-002",
        "threat_type": "phishing",
        "severity": "medium",
        "description": "Phishing campaign targeting employees",
        "indicators": ["phish-site.com", "suspicious-email@domain.com"],
        "source": "email_gateway",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "campaign_name": "CEO Fraud",
            "target_department": "finance",
            "email_count": 150
        }
    }
    
    # Create threat record in DynamoDB
    print("Creating threat record in DynamoDB...")
    result = dynamodb_service.create_threat_record(
        threat_data=threat_data,
        threat_id="THREAT-002",
        threat_type="phishing",
        severity="medium",
        source="email_gateway"
    )
    
    if result['success']:
        print(f"✅ Successfully created threat record: {result['threat_id']}")
        
        # Query threats by type
        print("Querying threats by type...")
        query_result = dynamodb_service.query_threats_by_type("phishing", limit=10)
        
        if query_result['success']:
            print(f"✅ Found {query_result['count']} phishing threats")
            for item in query_result['items'][:3]:  # Show first 3
                print(f"  - {item['threat_id']}: {item['data']['description']}")
        else:
            print(f"❌ Failed to query threats: {query_result['error']}")
    else:
        print(f"❌ Failed to create threat record: {result['error']}")


def example_cloudwatch_operations():
    """Example CloudWatch operations for monitoring and logging."""
    print("\n=== CloudWatch Operations Example ===")
    
    # Initialize AWS config and CloudWatch service
    config = AWSConfig.from_env()
    cloudwatch_service = CloudWatchService(config)
    
    # Put threat metrics
    print("Putting threat metrics to CloudWatch...")
    metric_result = cloudwatch_service.put_threat_metric(
        threat_type="malware",
        severity="high",
        count=5,
        source="automated_scanner"
    )
    
    if metric_result['success']:
        print(f"✅ Successfully put threat metrics for {metric_result['threat_type']}")
        
        # Log threat event
        print("Logging threat event to CloudWatch...")
        log_result = cloudwatch_service.log_threat_event(
            threat_id="THREAT-003",
            event_type="detection",
            description="New malware variant detected",
            severity="high",
            additional_data={
                "malware_family": "Emotet",
                "detection_method": "behavioral_analysis"
            }
        )
        
        if log_result['success']:
            print(f"✅ Successfully logged threat event to {log_result['log_group']}")
        else:
            print(f"❌ Failed to log threat event: {log_result['error']}")
    else:
        print(f"❌ Failed to put threat metrics: {metric_result['error']}")


def example_ses_operations():
    """Example SES operations for email notifications."""
    print("\n=== SES Operations Example ===")
    
    # Initialize AWS config and SES service
    config = AWSConfig.from_env()
    ses_service = SESService(config, from_email="threat-intel@yourdomain.com")
    
    # Example threat data for alert
    threat_data = {
        "threat_id": "THREAT-004",
        "threat_type": "apt",
        "severity": "critical",
        "description": "Advanced persistent threat targeting executive accounts",
        "indicators": ["apt-group.com", "192.168.1.200"],
        "source": "siem",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "apt_group": "APT29",
            "target_organization": "government",
            "attack_stage": "persistence"
        }
    }
    
    # Send threat alert email
    print("Sending threat alert email...")
    alert_result = ses_service.send_threat_alert(
        to_addresses=["security-team@yourdomain.com", "admin@yourdomain.com"],
        threat_data=threat_data,
        alert_type="critical",
        severity="critical"
    )
    
    if alert_result['success']:
        print(f"✅ Successfully sent threat alert: {alert_result['message_id']}")
        
        # Example daily report data
        report_data = {
            "total_threats": 25,
            "new_threats": 8,
            "critical_threats": 2,
            "high_severity": 5,
            "medium_severity": 12,
            "low_severity": 6,
            "threat_types": {
                "malware": 10,
                "phishing": 8,
                "apt": 3,
                "ddos": 4
            },
            "top_sources": [
                {"source": "automated_scanner", "count": 15},
                {"source": "siem", "count": 6},
                {"source": "manual_review", "count": 4}
            ],
            "recent_alerts": [
                {"threat_id": "THREAT-001", "description": "Malware detected", "severity": "high"},
                {"threat_id": "THREAT-002", "description": "Phishing campaign", "severity": "medium"}
            ]
        }
        
        # Send daily report
        print("Sending daily threat report...")
        report_result = ses_service.send_daily_report(
            to_addresses=["management@yourdomain.com"],
            report_data=report_data
        )
        
        if report_result['success']:
            print(f"✅ Successfully sent daily report: {report_result['message_id']}")
        else:
            print(f"❌ Failed to send daily report: {report_result['error']}")
    else:
        print(f"❌ Failed to send threat alert: {alert_result['error']}")


def example_lambda_operations():
    """Example Lambda operations for serverless processing."""
    print("\n=== Lambda Operations Example ===")
    
    # Initialize AWS config and Lambda service
    config = AWSConfig.from_env()
    lambda_service = LambdaService(config)
    
    # Example threat data for analysis
    threat_data = {
        "threat_id": "THREAT-005",
        "threat_type": "malware",
        "severity": "high",
        "description": "Suspicious file detected",
        "indicators": ["suspicious-file.exe", "malicious-hash-123"],
        "source": "endpoint_protection",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "file_name": "suspicious-file.exe",
            "file_hash": "abc123def456",
            "file_size": 1024000,
            "detection_engine": "endpoint_protection"
        }
    }
    
    # Invoke threat analysis Lambda function
    print("Invoking threat analysis Lambda function...")
    analysis_result = lambda_service.invoke_threat_analysis(
        threat_data=threat_data,
        analysis_type="advanced"
    )
    
    if analysis_result['success']:
        print(f"✅ Successfully invoked threat analysis: {analysis_result['status_code']}")
        
        # Invoke threat enrichment Lambda function
        print("Invoking threat enrichment Lambda function...")
        enrichment_result = lambda_service.invoke_threat_enrichment(
            threat_indicators=["suspicious-file.exe", "malicious-hash-123"],
            enrichment_sources=["virustotal", "abuseipdb"]
        )
        
        if enrichment_result['success']:
            print(f"✅ Successfully invoked threat enrichment: {enrichment_result['status_code']}")
        else:
            print(f"❌ Failed to invoke threat enrichment: {enrichment_result['error']}")
    else:
        print(f"❌ Failed to invoke threat analysis: {analysis_result['error']}")


def example_comprehensive_workflow():
    """Example comprehensive threat intelligence workflow with KMS encryption."""
    print("\n=== Comprehensive Workflow Example with KMS Encryption ===")
    
    # Initialize AWS config
    config = AWSConfig.from_env()
    kms_key_id = os.getenv('KMS_KEY_ID')
    
    # Initialize services with KMS encryption
    s3_service = S3Service(config, bucket_name="threat-intelligence-bucket", kms_key_id=kms_key_id)
    dynamodb_service = DynamoDBService(config, table_name="threat-intelligence")
    cloudwatch_service = CloudWatchService(config)
    ses_service = SESService(config)
    
    # Example threat data
    threat_data = {
        "threat_id": "THREAT-006",
        "threat_type": "ransomware",
        "severity": "critical",
        "description": "Ransomware attack targeting healthcare systems",
        "indicators": ["ransomware-domain.com", "malicious-payload.exe", "192.168.1.200"],
        "source": "siem_alert",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "ransomware_family": "WannaCry",
            "target_sector": "healthcare",
            "affected_systems": 50,
            "ransom_amount": "$500,000"
        }
    }
    
    results = {}
    
    # 1. Store threat data in S3 with KMS encryption
    print("1. Storing threat data in S3 with KMS encryption...")
    s3_result = s3_service.upload_threat_data(threat_data, "THREAT-006", "ransomware")
    results['s3'] = s3_result
    
    if s3_result['success']:
        encryption_type = s3_result.get('encryption', 'Unknown')
        print(f"   ✅ S3 Storage: {s3_result['key']} (Encryption: {encryption_type})")
    else:
        print(f"   ❌ S3 Storage failed: {s3_result['error']}")

    # 2. Store threat record in DynamoDB
    print("2. Storing threat record in DynamoDB...")
    dynamodb_result = dynamodb_service.create_threat_record(
        threat_data, "THREAT-006", "ransomware", "critical", "endpoint_protection"
    )
    results['dynamodb'] = dynamodb_result
    if dynamodb_result['success']:
        print(f"   ✅ DynamoDB Record: {dynamodb_result['threat_id']}")
    else:
        print(f"   ❌ DynamoDB Record failed: {dynamodb_result['error']}")

    # 3. Send metrics to CloudWatch
    print("3. Sending metrics to CloudWatch...")
    metrics_result = cloudwatch_service.put_threat_metric(
        "ransomware", "critical", 1, "endpoint_protection"
    )
    results['cloudwatch'] = metrics_result
    if metrics_result['success']:
        print(f"   ✅ CloudWatch Metrics: {metrics_result['threat_type']}")
    else:
        print(f"   ❌ CloudWatch Metrics failed: {metrics_result['error']}")

    # 4. Log the event
    print("4. Logging threat event...")
    log_result = cloudwatch_service.log_threat_event(
        "THREAT-006", "detection", "Ransomware attack detected", "critical"
    )
    results['cloudwatch_log'] = log_result
    if log_result['success']:
        print(f"   ✅ CloudWatch Event Log: {log_result['event_id']}")
    else:
        print(f"   ❌ CloudWatch Event Log failed: {log_result['error']}")

    # 5. Invoke analysis Lambda function
    print("5. Invoking threat analysis...")
    lambda_result = lambda_service.invoke_threat_analysis(threat_data, "advanced")
    results['lambda_analysis'] = lambda_result
    if lambda_result['success']:
        print(f"   ✅ Lambda Analysis: {lambda_result['status_code']}")
    else:
        print(f"   ❌ Lambda Analysis failed: {lambda_result['error']}")

    # 6. Send critical alert
    print("6. Sending critical alert...")
    alert_result = ses_service.send_threat_alert(
        ["incident-response@yourdomain.com", "security-team@yourdomain.com"],
        threat_data, "critical", "critical"
    )
    results['ses_alert'] = alert_result
    if alert_result['success']:
        print(f"   ✅ Email Alert: {alert_result['message_id']}")
    else:
        print(f"   ❌ Email Alert failed: {alert_result['error']}")

    # Print summary
    print("\n=== Workflow Summary ===")
    workflow_results = [
        ("S3 Storage with KMS", s3_result['success']),
        ("DynamoDB Storage", dynamodb_result['success']),
        ("CloudWatch Metrics", metrics_result['success']),
        ("Email Alert", alert_result['success'])
    ]
    
    for service, success in workflow_results:
        status = "✅" if success else "❌"
        print(f"{status} {service}")
    
    # Print encryption details
    if s3_result['success']:
        encryption_type = s3_result.get('encryption', 'Unknown')
        kms_key_used = s3_result.get('kms_key_id', 'None')
        print(f"\n🔐 Encryption Details:")
        print(f"   Type: {encryption_type}")
        print(f"   KMS Key ID: {kms_key_used}")


def main():
    """Main function to run all examples."""
    print("AWS Services Examples for Threat Intelligence Platform")
    print("=" * 60)
    
    try:
        # Run individual service examples
        example_s3_operations()
        example_kms_operations() # Added KMS example
        example_dynamodb_operations()
        example_cloudwatch_operations()
        example_ses_operations()
        example_lambda_operations()
        
        # Run integrated workflow example
        example_comprehensive_workflow()
        
        print("\n" + "=" * 60)
        print("✅ All examples completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        print("Make sure you have:")
        print("1. AWS credentials configured (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)")
        print("2. AWS region set (AWS_REGION)")
        print("3. Required AWS services enabled (S3, DynamoDB, CloudWatch, SES, Lambda)")
        print("4. Appropriate IAM permissions")


if __name__ == "__main__":
    main() 
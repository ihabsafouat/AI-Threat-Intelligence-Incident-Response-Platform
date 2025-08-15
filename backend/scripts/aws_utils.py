#!/usr/bin/env python3
"""
AWS Utilities for Threat Intelligence

Quick utility functions for common AWS operations in threat intelligence workflows with KMS encryption.
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.aws import (
    AWSConfig, S3Service, DynamoDBService, 
    CloudWatchService, SESService, LambdaService
)


class ThreatIntelligenceAWS:
    """Utility class for threat intelligence AWS operations with KMS encryption."""
    
    def __init__(self, region: Optional[str] = None, kms_key_id: Optional[str] = None):
        """
        Initialize AWS services.
        
        Args:
            region: AWS region
            kms_key_id: KMS key ID for encryption
        """
        self.config = AWSConfig.from_env()
        if region:
            self.config.region = region
        if kms_key_id:
            self.config.kms_key_id = kms_key_id
        
        # Initialize S3 service with KMS encryption
        self.s3_service = S3Service(
            self.config, 
            kms_key_id=self.config.kms_key_id
        )
        self.dynamodb_service = DynamoDBService(self.config)
        self.cloudwatch_service = CloudWatchService(self.config)
        self.ses_service = SESService(self.config)
        self.lambda_service = LambdaService(self.config)
        
        # Log encryption configuration
        if self.config.kms_key_id:
            print(f"Using KMS encryption with key: {self.config.kms_key_id}")
        else:
            print("Warning: No KMS key ID provided, using AES256 encryption")
    
    def store_threat(self, threat_data: Dict[str, Any], compress: bool = True) -> Dict[str, Any]:
        """
        Store threat data in both S3 and DynamoDB.
        
        Args:
            threat_data: Threat intelligence data
            compress: Whether to compress S3 data
            
        Returns:
            Storage result dictionary
        """
        threat_id = threat_data.get('threat_id', f"THREAT-{datetime.now().strftime('%Y%m%d%H%M%S')}")
        threat_type = threat_data.get('threat_type', 'unknown')
        severity = threat_data.get('severity', 'medium')
        source = threat_data.get('source', 'manual')
        
        results = {}
        
        # Store in S3
        s3_result = self.s3_service.upload_threat_data(
            threat_data, threat_id, threat_type, compress
        )
        results['s3'] = s3_result
        
        # Store in DynamoDB
        dynamodb_result = self.dynamodb_service.create_threat_record(
            threat_data, threat_id, threat_type, severity, source
        )
        results['dynamodb'] = dynamodb_result
        
        # Send metrics
        metric_result = self.cloudwatch_service.put_threat_metric(
            threat_type, severity, 1, source
        )
        results['metrics'] = metric_result
        
        # Log event
        log_result = self.cloudwatch_service.log_threat_event(
            threat_id, 'storage', f'Threat {threat_id} stored', severity
        )
        results['logging'] = log_result
        
        return {
            'success': all(r.get('success', False) for r in results.values()),
            'threat_id': threat_id,
            'results': results
        }
    
    def search_threats(self, threat_type: Optional[str] = None, severity: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
        """
        Search threats in DynamoDB.
        
        Args:
            threat_type: Filter by threat type
            severity: Filter by severity
            limit: Maximum number of results
            
        Returns:
            Search results dictionary
        """
        if threat_type:
            return self.dynamodb_service.query_threats_by_type(threat_type, limit)
        elif severity:
            return self.dynamodb_service.query_threats_by_severity(severity, limit)
        else:
            return self.dynamodb_service.scan_threats(limit=limit)
    
    def get_threat(self, threat_id: str) -> Dict[str, Any]:
        """
        Get threat data from DynamoDB.
        
        Args:
            threat_id: Threat identifier
            
        Returns:
            Threat data dictionary
        """
        return self.dynamodb_service.get_threat_record(threat_id)
    
    def send_alert(self, threat_data: Dict[str, Any], recipients: List[str], alert_type: str = 'standard') -> Dict[str, Any]:
        """
        Send threat alert email.
        
        Args:
            threat_data: Threat data
            recipients: List of email recipients
            alert_type: Type of alert
            
        Returns:
            Alert result dictionary
        """
        severity = threat_data.get('severity', 'medium')
        return self.ses_service.send_threat_alert(recipients, threat_data, alert_type, severity)
    
    def analyze_threat(self, threat_data: Dict[str, Any], analysis_type: str = 'basic') -> Dict[str, Any]:
        """
        Analyze threat using Lambda function.
        
        Args:
            threat_data: Threat data to analyze
            analysis_type: Type of analysis
            
        Returns:
            Analysis result dictionary
        """
        return self.lambda_service.invoke_threat_analysis(threat_data, analysis_type)
    
    def get_metrics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get threat metrics from CloudWatch.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Metrics dictionary
        """
        return self.cloudwatch_service.get_threat_metrics(hours=hours)
    
    def list_s3_files(self, data_type: str = 'threat_intelligence', max_keys: int = 100) -> Dict[str, Any]:
        """
        List threat files in S3.
        
        Args:
            data_type: Type of threat data
            max_keys: Maximum number of keys
            
        Returns:
            Files list dictionary
        """
        return self.s3_service.list_threat_files(data_type, max_keys=max_keys)


def main():
    """Main function for command-line interface."""
    parser = argparse.ArgumentParser(description='AWS Utilities for Threat Intelligence')
    parser.add_argument('--region', help='AWS region')
    parser.add_argument('--kms-key-id', help='KMS key ID for S3 encryption')
    parser.add_argument('--action', required=True, choices=[
        'store', 'search', 'get', 'alert', 'analyze', 'metrics', 'list-files'
    ], help='Action to perform')
    parser.add_argument('--threat-id', help='Threat ID for get action')
    parser.add_argument('--threat-type', help='Threat type filter')
    parser.add_argument('--severity', help='Severity filter')
    parser.add_argument('--file', help='JSON file with threat data')
    parser.add_argument('--recipients', nargs='+', help='Email recipients for alerts')
    parser.add_argument('--analysis-type', default='basic', help='Analysis type')
    parser.add_argument('--hours', type=int, default=24, help='Hours for metrics')
    parser.add_argument('--limit', type=int, default=50, help='Result limit')
    
    args = parser.parse_args()
    
    # Initialize AWS utilities
    aws_utils = ThreatIntelligenceAWS(args.region, args.kms_key_id)
    
    try:
        if args.action == 'store':
            if not args.file:
                print("❌ Error: --file required for store action")
                return
            
            with open(args.file, 'r') as f:
                threat_data = json.load(f)
            
            result = aws_utils.store_threat(threat_data)
            if result['success']:
                print(f"✅ Successfully stored threat {result['threat_id']}")
            else:
                print("❌ Failed to store threat")
                print(json.dumps(result, indent=2))
        
        elif args.action == 'search':
            result = aws_utils.search_threats(
                threat_type=args.threat_type,
                severity=args.severity,
                limit=args.limit
            )
            
            if result['success']:
                print(f"✅ Found {result['count']} threats")
                for item in result['items'][:5]:  # Show first 5
                    print(f"  - {item['threat_id']}: {item['data'].get('description', 'No description')}")
            else:
                print(f"❌ Search failed: {result['error']}")
        
        elif args.action == 'get':
            if not args.threat_id:
                print("❌ Error: --threat-id required for get action")
                return
            
            result = aws_utils.get_threat(args.threat_id)
            if result['success']:
                print(f"✅ Found threat {args.threat_id}")
                print(json.dumps(result['item'], indent=2))
            else:
                print(f"❌ Threat not found: {result['error']}")
        
        elif args.action == 'alert':
            if not args.file or not args.recipients:
                print("❌ Error: --file and --recipients required for alert action")
                return
            
            with open(args.file, 'r') as f:
                threat_data = json.load(f)
            
            result = aws_utils.send_alert(threat_data, args.recipients)
            if result['success']:
                print(f"✅ Alert sent: {result['message_id']}")
            else:
                print(f"❌ Alert failed: {result['error']}")
        
        elif args.action == 'analyze':
            if not args.file:
                print("❌ Error: --file required for analyze action")
                return
            
            with open(args.file, 'r') as f:
                threat_data = json.load(f)
            
            result = aws_utils.analyze_threat(threat_data, args.analysis_type)
            if result['success']:
                print(f"✅ Analysis completed: {result['status_code']}")
                if 'payload' in result:
                    print(json.dumps(result['payload'], indent=2))
            else:
                print(f"❌ Analysis failed: {result['error']}")
        
        elif args.action == 'metrics':
            result = aws_utils.get_metrics(args.hours)
            if result['success']:
                print(f"✅ Retrieved metrics for last {args.hours} hours")
                print(json.dumps(result, indent=2))
            else:
                print(f"❌ Metrics failed: {result['error']}")
        
        elif args.action == 'list-files':
            result = aws_utils.list_s3_files(max_keys=args.limit)
            if result['success']:
                print(f"✅ Found {result['count']} files")
                for file_info in result['files'][:10]:  # Show first 10
                    print(f"  - {file_info['key']} ({file_info['size']} bytes)")
            else:
                print(f"❌ List files failed: {result['error']}")
    
    except Exception as e:
        print(f"❌ Error: {e}")
        print("Make sure you have AWS credentials configured and appropriate permissions.")


if __name__ == "__main__":
    main() 
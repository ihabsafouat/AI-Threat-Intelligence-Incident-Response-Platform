"""
AWS S3 Storage Service for Raw Data
Provides comprehensive S3 storage capabilities for threat intelligence raw data.
"""

import json
import logging
import gzip
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import asyncio

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from pydantic import BaseModel

from app.core.config import settings

logger = logging.getLogger(__name__)


class S3StorageConfig(BaseModel):
    """S3 Storage Configuration"""
    bucket_name: str
    region: str = "us-east-1"
    folder_structure: Dict[str, str] = {
        "raw_data": "raw/",
        "processed_data": "processed/",
        "archived_data": "archive/",
        "backup_data": "backup/",
        "logs": "logs/",
        "temp": "temp/"
    }
    lifecycle_policies: Dict[str, Dict[str, Any]] = {
        "hot_data": {"days": 30, "storage_class": "STANDARD"},
        "warm_data": {"days": 90, "storage_class": "STANDARD_IA"},
        "cold_data": {"days": 365, "storage_class": "GLACIER"},
        "archive_data": {"days": 2555, "storage_class": "DEEP_ARCHIVE"}
    }
    compression_enabled: bool = True
    encryption_enabled: bool = True


class S3StorageService:
    """Comprehensive S3 storage service for raw data"""
    
    def __init__(self, config: Optional[S3StorageConfig] = None):
        self.config = config or S3StorageConfig(
            bucket_name=settings.S3_BUCKET or "threat-intelligence-platform"
        )
        self.s3_client = boto3.client('s3', region_name=self.config.region)
        self.s3_resource = boto3.resource('s3', region_name=self.config.region)
        self.bucket = self.s3_resource.Bucket(self.config.bucket_name)
        
        # Ensure bucket exists
        self._ensure_bucket_exists()
    
    def _ensure_bucket_exists(self):
        """Ensure S3 bucket exists, create if it doesn't"""
        try:
            self.s3_client.head_bucket(Bucket=self.config.bucket_name)
            logger.info(f"S3 bucket {self.config.bucket_name} exists")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                logger.info(f"Creating S3 bucket {self.config.bucket_name}")
                self._create_bucket()
            else:
                raise
    
    def _create_bucket(self):
        """Create S3 bucket with proper configuration"""
        try:
            bucket_config = {
                'Bucket': self.config.bucket_name,
                'CreateBucketConfiguration': {
                    'LocationConstraint': self.config.region
                }
            }
            
            # Remove LocationConstraint for us-east-1
            if self.config.region == 'us-east-1':
                bucket_config.pop('CreateBucketConfiguration')
            
            self.s3_client.create_bucket(**bucket_config)
            
            # Configure bucket settings
            self._configure_bucket()
            
            logger.info(f"Successfully created S3 bucket {self.config.bucket_name}")
        except ClientError as e:
            logger.error(f"Failed to create S3 bucket: {e}")
            raise
    
    def _configure_bucket(self):
        """Configure bucket with versioning, encryption, and lifecycle policies"""
        try:
            # Enable versioning
            self.s3_client.put_bucket_versioning(
                Bucket=self.config.bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            # Configure encryption
            if self.config.encryption_enabled:
                self.s3_client.put_bucket_encryption(
                    Bucket=self.config.bucket_name,
                    ServerSideEncryptionConfiguration={
                        'Rules': [{
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }]
                    }
                )
            
            # Configure lifecycle policies
            self._setup_lifecycle_policies()
            
            logger.info(f"Successfully configured S3 bucket {self.config.bucket_name}")
        except ClientError as e:
            logger.error(f"Failed to configure S3 bucket: {e}")
            raise
    
    def _setup_lifecycle_policies(self):
        """Setup lifecycle policies for data retention"""
        try:
            lifecycle_rules = []
            
            for policy_name, policy_config in self.config.lifecycle_policies.items():
                rule = {
                    'ID': f'{policy_name}_rule',
                    'Status': 'Enabled',
                    'Filter': {
                        'Prefix': f'{policy_name}/'
                    },
                    'Transitions': [{
                        'Days': policy_config['days'],
                        'StorageClass': policy_config['storage_class']
                    }]
                }
                lifecycle_rules.append(rule)
            
            self.s3_client.put_bucket_lifecycle_configuration(
                Bucket=self.config.bucket_name,
                LifecycleConfiguration={'Rules': lifecycle_rules}
            )
            
            logger.info("Successfully configured lifecycle policies")
        except ClientError as e:
            logger.error(f"Failed to configure lifecycle policies: {e}")
            raise
    
    async def store_raw_data(
        self,
        data: Union[Dict[str, Any], List[Dict[str, Any]]],
        data_type: str,
        source: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Store raw data in S3 with proper organization"""
        try:
            # Generate file key
            timestamp = datetime.utcnow().strftime('%Y/%m/%d/%H%M%S')
            data_hash = self._generate_data_hash(data)
            file_key = f"{self.config.folder_structure['raw_data']}{data_type}/{source}/{timestamp}_{data_hash}.json"
            
            # Prepare data for storage
            storage_data = {
                'data': data,
                'metadata': {
                    'data_type': data_type,
                    'source': source,
                    'ingestion_timestamp': datetime.utcnow().isoformat(),
                    'data_hash': data_hash,
                    'record_count': len(data) if isinstance(data, list) else 1,
                    **(metadata or {})
                }
            }
            
            # Convert to JSON
            json_data = json.dumps(storage_data, default=str, indent=2)
            
            # Compress if enabled
            if self.config.compression_enabled:
                compressed_data = gzip.compress(json_data.encode('utf-8'))
                file_key = file_key.replace('.json', '.json.gz')
                content_encoding = 'gzip'
            else:
                compressed_data = json_data.encode('utf-8')
                content_encoding = None
            
            # Upload to S3
            upload_params = {
                'Bucket': self.config.bucket_name,
                'Key': file_key,
                'Body': compressed_data,
                'ContentType': 'application/json',
                'Metadata': {
                    'data_type': data_type,
                    'source': source,
                    'ingestion_timestamp': datetime.utcnow().isoformat(),
                    'data_hash': data_hash
                }
            }
            
            if content_encoding:
                upload_params['ContentEncoding'] = content_encoding
            
            self.s3_client.put_object(**upload_params)
            
            logger.info(f"Successfully stored raw data: {file_key}")
            return file_key
            
        except Exception as e:
            logger.error(f"Failed to store raw data: {e}")
            raise
    
    async def store_processed_data(
        self,
        data: Dict[str, Any],
        data_type: str,
        processing_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Store processed data in S3"""
        try:
            timestamp = datetime.utcnow().strftime('%Y/%m/%d/%H%M%S')
            file_key = f"{self.config.folder_structure['processed_data']}{data_type}/{processing_id}_{timestamp}.json"
            
            storage_data = {
                'data': data,
                'metadata': {
                    'data_type': data_type,
                    'processing_id': processing_id,
                    'processing_timestamp': datetime.utcnow().isoformat(),
                    **(metadata or {})
                }
            }
            
            json_data = json.dumps(storage_data, default=str, indent=2)
            
            self.s3_client.put_object(
                Bucket=self.config.bucket_name,
                Key=file_key,
                Body=json_data.encode('utf-8'),
                ContentType='application/json',
                Metadata={
                    'data_type': data_type,
                    'processing_id': processing_id,
                    'processing_timestamp': datetime.utcnow().isoformat()
                }
            )
            
            logger.info(f"Successfully stored processed data: {file_key}")
            return file_key
            
        except Exception as e:
            logger.error(f"Failed to store processed data: {e}")
            raise
    
    async def retrieve_data(self, file_key: str) -> Dict[str, Any]:
        """Retrieve data from S3"""
        try:
            response = self.s3_client.get_object(
                Bucket=self.config.bucket_name,
                Key=file_key
            )
            
            # Check if data is compressed
            content_encoding = response.get('ContentEncoding')
            data = response['Body'].read()
            
            if content_encoding == 'gzip':
                data = gzip.decompress(data)
            
            return json.loads(data.decode('utf-8'))
            
        except ClientError as e:
            logger.error(f"Failed to retrieve data from S3: {e}")
            raise
    
    async def list_data_files(
        self,
        data_type: Optional[str] = None,
        source: Optional[str] = None,
        date_range: Optional[tuple] = None
    ) -> List[Dict[str, Any]]:
        """List data files in S3 with optional filtering"""
        try:
            prefix = self.config.folder_structure['raw_data']
            if data_type:
                prefix += f"{data_type}/"
            if source:
                prefix += f"{source}/"
            
            paginator = self.s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(
                Bucket=self.config.bucket_name,
                Prefix=prefix
            )
            
            files = []
            for page in page_iterator:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        # Apply date range filter if specified
                        if date_range:
                            start_date, end_date = date_range
                            if not (start_date <= obj['LastModified'] <= end_date):
                                continue
                        
                        files.append({
                            'key': obj['Key'],
                            'size': obj['Size'],
                            'last_modified': obj['LastModified'],
                            'storage_class': obj['StorageClass']
                        })
            
            return files
            
        except Exception as e:
            logger.error(f"Failed to list data files: {e}")
            raise
    
    async def archive_data(self, file_key: str, archive_reason: str = "data_retention") -> str:
        """Archive data to long-term storage"""
        try:
            # Copy to archive folder
            archive_key = file_key.replace(
                self.config.folder_structure['raw_data'],
                self.config.folder_structure['archived_data']
            )
            
            self.s3_client.copy_object(
                Bucket=self.config.bucket_name,
                CopySource={'Bucket': self.config.bucket_name, 'Key': file_key},
                Key=archive_key,
                Metadata={
                    'archive_reason': archive_reason,
                    'archive_timestamp': datetime.utcnow().isoformat(),
                    'original_key': file_key
                }
            )
            
            # Delete original file
            self.s3_client.delete_object(
                Bucket=self.config.bucket_name,
                Key=file_key
            )
            
            logger.info(f"Successfully archived data: {file_key} -> {archive_key}")
            return archive_key
            
        except Exception as e:
            logger.error(f"Failed to archive data: {e}")
            raise
    
    async def backup_data(self, file_key: str) -> str:
        """Create backup of data"""
        try:
            backup_key = file_key.replace(
                self.config.folder_structure['raw_data'],
                self.config.folder_structure['backup_data']
            )
            
            self.s3_client.copy_object(
                Bucket=self.config.bucket_name,
                CopySource={'Bucket': self.config.bucket_name, 'Key': file_key},
                Key=backup_key,
                Metadata={
                    'backup_timestamp': datetime.utcnow().isoformat(),
                    'original_key': file_key
                }
            )
            
            logger.info(f"Successfully backed up data: {file_key} -> {backup_key}")
            return backup_key
            
        except Exception as e:
            logger.error(f"Failed to backup data: {e}")
            raise
    
    async def cleanup_old_data(self, days_old: int = 90) -> int:
        """Clean up old data files"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            files_to_delete = []
            
            # List old files
            paginator = self.s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(
                Bucket=self.config.bucket_name,
                Prefix=self.config.folder_structure['raw_data']
            )
            
            for page in page_iterator:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        if obj['LastModified'] < cutoff_date:
                            files_to_delete.append({'Key': obj['Key']})
            
            # Delete old files in batches
            if files_to_delete:
                for i in range(0, len(files_to_delete), 1000):
                    batch = files_to_delete[i:i+1000]
                    self.s3_client.delete_objects(
                        Bucket=self.config.bucket_name,
                        Delete={'Objects': batch}
                    )
            
            logger.info(f"Successfully cleaned up {len(files_to_delete)} old files")
            return len(files_to_delete)
            
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")
            raise
    
    def _generate_data_hash(self, data: Union[Dict[str, Any], List[Dict[str, Any]]]) -> str:
        """Generate hash for data content"""
        data_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.md5(data_str.encode()).hexdigest()[:8]
    
    async def get_storage_metrics(self) -> Dict[str, Any]:
        """Get storage metrics and statistics"""
        try:
            metrics = {
                'total_files': 0,
                'total_size': 0,
                'files_by_type': {},
                'files_by_source': {},
                'storage_class_distribution': {}
            }
            
            paginator = self.s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=self.config.bucket_name)
            
            for page in page_iterator:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        metrics['total_files'] += 1
                        metrics['total_size'] += obj['Size']
                        
                        # Parse file key to get type and source
                        key_parts = obj['Key'].split('/')
                        if len(key_parts) >= 3:
                            data_type = key_parts[1] if key_parts[0] == 'raw' else 'unknown'
                            source = key_parts[2] if len(key_parts) > 2 else 'unknown'
                            
                            metrics['files_by_type'][data_type] = metrics['files_by_type'].get(data_type, 0) + 1
                            metrics['files_by_source'][source] = metrics['files_by_source'].get(source, 0) + 1
                        
                        # Storage class distribution
                        storage_class = obj.get('StorageClass', 'STANDARD')
                        metrics['storage_class_distribution'][storage_class] = metrics['storage_class_distribution'].get(storage_class, 0) + 1
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get storage metrics: {e}")
            raise 
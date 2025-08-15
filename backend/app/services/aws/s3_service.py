"""
S3 Service Module

Handles file uploads, downloads, and management in Amazon S3 with KMS encryption.
"""

import os
import json
import gzip
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union, BinaryIO
from pathlib import Path
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import logging

from .config import AWSConfig

logger = logging.getLogger(__name__)


class S3Service:
    """Amazon S3 Service for file operations with KMS encryption"""
    
    def __init__(self, config: AWSConfig, bucket_name: Optional[str] = None, kms_key_id: Optional[str] = None):
        """
        Initialize S3 service.
        
        Args:
            config: AWS configuration
            bucket_name: S3 bucket name (defaults to environment variable)
            kms_key_id: KMS key ID for encryption (defaults to environment variable)
        """
        self.config = config
        self.bucket_name = bucket_name or os.getenv('S3_BUCKET')
        self.kms_key_id = kms_key_id or os.getenv('KMS_KEY_ID')
        self.s3_client = config.get_client('s3')
        self.s3_resource = config.get_resource('s3')
        
        if not self.bucket_name:
            raise ValueError("S3 bucket name is required")
        
        # Log encryption configuration
        if self.kms_key_id:
            logger.info(f"Using KMS encryption with key: {self.kms_key_id}")
        else:
            logger.warning("No KMS key ID provided, falling back to AES256 encryption")
    
    def upload_file(
        self,
        file_path: Union[str, Path],
        s3_key: str,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
        encrypt: bool = True
    ) -> Dict[str, Any]:
        """
        Upload a file to S3 with KMS encryption.
        
        Args:
            file_path: Local file path
            s3_key: S3 object key
            content_type: Content type of the file
            metadata: Additional metadata
            encrypt: Whether to encrypt the file
            
        Returns:
            Upload result dictionary
        """
        try:
            extra_args = {}
            if content_type:
                extra_args['ContentType'] = content_type
            if encrypt:
                if self.kms_key_id:
                    extra_args['ServerSideEncryption'] = 'aws:kms'
                    extra_args['SSEKMSKeyId'] = self.kms_key_id
                else:
                    extra_args['ServerSideEncryption'] = 'AES256'
            if metadata:
                extra_args['Metadata'] = metadata
            
            self.s3_client.upload_file(
                str(file_path),
                self.bucket_name,
                s3_key,
                ExtraArgs=extra_args
            )
            
            encryption_type = 'KMS' if self.kms_key_id and encrypt else 'AES256' if encrypt else 'None'
            logger.info(f"Successfully uploaded {file_path} to s3://{self.bucket_name}/{s3_key} with {encryption_type} encryption")
            
            return {
                'success': True,
                'bucket': self.bucket_name,
                'key': s3_key,
                'size': os.path.getsize(file_path),
                'encryption': encryption_type,
                'kms_key_id': self.kms_key_id if self.kms_key_id and encrypt else None
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to upload file: {e}")
            return {'success': False, 'error': str(e)}
    
    def upload_threat_data(
        self,
        threat_data: Dict[str, Any],
        threat_id: str,
        data_type: str = 'threat_intelligence',
        compress: bool = True
    ) -> Dict[str, Any]:
        """
        Upload threat intelligence data to S3 with KMS encryption.
        
        Args:
            threat_data: Threat data dictionary
            threat_id: Unique threat identifier
            data_type: Type of threat data
            compress: Whether to compress the data
            
        Returns:
            Upload result dictionary
        """
        try:
            # Create timestamp for versioning
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Create S3 key with organization
            s3_key = f"threat-intelligence/{data_type}/{threat_id}/{timestamp}.json"
            
            # Prepare metadata
            metadata = {
                'threat_id': threat_id,
                'data_type': data_type,
                'upload_timestamp': timestamp,
                'content_hash': hashlib.md5(json.dumps(threat_data, sort_keys=True).encode()).hexdigest()
            }
            
            # Convert data to JSON
            json_data = json.dumps(threat_data, indent=2, default=str)
            
            if compress:
                # Compress data
                compressed_data = gzip.compress(json_data.encode('utf-8'))
                s3_key = s3_key.replace('.json', '.json.gz')
                content_type = 'application/gzip'
                data_to_upload = compressed_data
            else:
                content_type = 'application/json'
                data_to_upload = json_data.encode('utf-8')
            
            # Prepare upload parameters with KMS encryption
            upload_params = {
                'Bucket': self.bucket_name,
                'Key': s3_key,
                'Body': data_to_upload,
                'ContentType': content_type,
                'Metadata': metadata
            }
            
            # Add encryption parameters
            if self.kms_key_id:
                upload_params['ServerSideEncryption'] = 'aws:kms'
                upload_params['SSEKMSKeyId'] = self.kms_key_id
            else:
                upload_params['ServerSideEncryption'] = 'AES256'
            
            # Upload to S3
            self.s3_client.put_object(**upload_params)
            
            encryption_type = 'KMS' if self.kms_key_id else 'AES256'
            logger.info(f"Successfully uploaded threat data {threat_id} to s3://{self.bucket_name}/{s3_key} with {encryption_type} encryption")
            
            return {
                'success': True,
                'bucket': self.bucket_name,
                'key': s3_key,
                'threat_id': threat_id,
                'data_type': data_type,
                'timestamp': timestamp,
                'compressed': compress,
                'size': len(data_to_upload),
                'encryption': encryption_type,
                'kms_key_id': self.kms_key_id
            }
            
        except Exception as e:
            logger.error(f"Failed to upload threat data: {e}")
            return {'success': False, 'error': str(e)}
    
    def download_file(
        self,
        s3_key: str,
        local_path: Union[str, Path],
        decompress: bool = False
    ) -> Dict[str, Any]:
        """
        Download a file from S3.
        
        Args:
            s3_key: S3 object key
            local_path: Local file path to save to
            decompress: Whether to decompress gzipped files
            
        Returns:
            Download result dictionary
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # Download file
            self.s3_client.download_file(self.bucket_name, s3_key, str(local_path))
            
            # Decompress if needed
            if decompress and s3_key.endswith('.gz'):
                with gzip.open(local_path, 'rb') as f_in:
                    decompressed_path = str(local_path).replace('.gz', '')
                    with open(decompressed_path, 'wb') as f_out:
                        f_out.write(f_in.read())
                os.remove(local_path)
                local_path = decompressed_path
            
            logger.info(f"Successfully downloaded s3://{self.bucket_name}/{s3_key} to {local_path}")
            
            return {
                'success': True,
                'local_path': str(local_path),
                'size': os.path.getsize(local_path)
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to download file: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_threat_data(self, threat_id: str, data_type: str = 'threat_intelligence') -> Dict[str, Any]:
        """
        Retrieve threat data from S3.
        
        Args:
            threat_id: Threat identifier
            data_type: Type of threat data
            
        Returns:
            Threat data dictionary
        """
        try:
            # List objects with the threat ID prefix
            prefix = f"threat-intelligence/{data_type}/{threat_id}/"
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix,
                MaxKeys=1
            )
            
            if 'Contents' not in response:
                return {'success': False, 'error': 'Threat data not found'}
            
            # Get the latest file
            latest_key = response['Contents'][0]['Key']
            
            # Download and parse the data
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=latest_key)
            
            if latest_key.endswith('.gz'):
                # Decompress gzipped data
                data = gzip.decompress(response['Body'].read()).decode('utf-8')
            else:
                data = response['Body'].read().decode('utf-8')
            
            threat_data = json.loads(data)
            
            return {
                'success': True,
                'threat_data': threat_data,
                'metadata': response.get('Metadata', {}),
                's3_key': latest_key
            }
            
        except Exception as e:
            logger.error(f"Failed to retrieve threat data: {e}")
            return {'success': False, 'error': str(e)}
    
    def list_threat_files(
        self,
        data_type: str = 'threat_intelligence',
        prefix: Optional[str] = None,
        max_keys: int = 100
    ) -> Dict[str, Any]:
        """
        List threat intelligence files in S3.
        
        Args:
            data_type: Type of threat data
            prefix: Optional prefix filter
            max_keys: Maximum number of keys to return
            
        Returns:
            List of S3 objects
        """
        try:
            s3_prefix = f"threat-intelligence/{data_type}/"
            if prefix:
                s3_prefix += prefix
            
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=s3_prefix,
                MaxKeys=max_keys
            )
            
            files = []
            if 'Contents' in response:
                for obj in response['Contents']:
                    files.append({
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'].isoformat(),
                        'etag': obj['ETag']
                    })
            
            return {
                'success': True,
                'files': files,
                'count': len(files),
                'prefix': s3_prefix
            }
            
        except Exception as e:
            logger.error(f"Failed to list threat files: {e}")
            return {'success': False, 'error': str(e)}
    
    def delete_file(self, s3_key: str) -> Dict[str, Any]:
        """
        Delete a file from S3.
        
        Args:
            s3_key: S3 object key
            
        Returns:
            Delete result dictionary
        """
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=s3_key)
            logger.info(f"Successfully deleted s3://{self.bucket_name}/{s3_key}")
            
            return {'success': True, 'key': s3_key}
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to delete file: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_file_url(self, s3_key: str, expires_in: int = 3600) -> str:
        """
        Generate a presigned URL for file access.
        
        Args:
            s3_key: S3 object key
            expires_in: URL expiration time in seconds
            
        Returns:
            Presigned URL
        """
        try:
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.bucket_name, 'Key': s3_key},
                ExpiresIn=expires_in
            )
            return url
        except Exception as e:
            logger.error(f"Failed to generate presigned URL: {e}")
            return ""
    
    def check_bucket_exists(self) -> bool:
        """
        Check if the S3 bucket exists.
        
        Returns:
            True if bucket exists, False otherwise
        """
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            return True
        except ClientError:
            return False 
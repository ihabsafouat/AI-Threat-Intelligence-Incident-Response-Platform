"""
AWS Configuration Module

Handles AWS credentials, regions, and service configurations including KMS support.
"""

import os
import boto3
from typing import Optional, Dict, Any
from botocore.config import Config
import logging

logger = logging.getLogger(__name__)


class AWSConfig:
    """AWS Configuration Manager with KMS support"""
    
    def __init__(
        self,
        region: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        session_token: Optional[str] = None,
        profile_name: Optional[str] = None,
        kms_key_id: Optional[str] = None
    ):
        """
        Initialize AWS configuration.
        
        Args:
            region: AWS region (defaults to environment variable)
            access_key_id: AWS access key ID (defaults to environment variable)
            secret_access_key: AWS secret access key (defaults to environment variable)
            session_token: AWS session token (defaults to environment variable)
            profile_name: AWS profile name for credentials
            kms_key_id: KMS key ID for encryption (defaults to environment variable)
        """
        self.region = region or os.getenv('AWS_REGION', 'us-east-1')
        self.access_key_id = access_key_id or os.getenv('AWS_ACCESS_KEY_ID')
        self.secret_access_key = secret_access_key or os.getenv('AWS_SECRET_ACCESS_KEY')
        self.session_token = session_token or os.getenv('AWS_SESSION_TOKEN')
        self.profile_name = profile_name or os.getenv('AWS_PROFILE')
        self.kms_key_id = kms_key_id or os.getenv('KMS_KEY_ID')
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate AWS configuration."""
        if not self.access_key_id or not self.secret_access_key:
            logger.warning("AWS credentials not provided. Using default credential chain.")
        
        if self.kms_key_id:
            logger.info(f"KMS key ID configured: {self.kms_key_id}")
        else:
            logger.warning("No KMS key ID provided. KMS encryption will not be available.")
    
    def get_session(self) -> boto3.Session:
        """
        Get boto3 session with configured credentials.
        
        Returns:
            boto3.Session: Configured AWS session
        """
        if self.profile_name:
            return boto3.Session(profile_name=self.profile_name, region_name=self.region)
        
        if self.access_key_id and self.secret_access_key:
            return boto3.Session(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                aws_session_token=self.session_token,
                region_name=self.region
            )
        
        return boto3.Session(region_name=self.region)
    
    def get_client(self, service_name: str, config: Optional[Config] = None) -> Any:
        """
        Get AWS service client.
        
        Args:
            service_name: AWS service name (e.g., 's3', 'dynamodb')
            config: Optional boto3 config
            
        Returns:
            AWS service client
        """
        session = self.get_session()
        return session.client(service_name, config=config)
    
    def get_resource(self, service_name: str, config: Optional[Config] = None) -> Any:
        """
        Get AWS service resource.
        
        Args:
            service_name: AWS service name (e.g., 's3', 'dynamodb')
            config: Optional boto3 config
            
        Returns:
            AWS service resource
        """
        session = self.get_session()
        return session.resource(service_name, config=config)
    
    def get_kms_client(self, config: Optional[Config] = None) -> Any:
        """
        Get AWS KMS client.
        
        Args:
            config: Optional boto3 config
            
        Returns:
            AWS KMS client
        """
        session = self.get_session()
        return session.client('kms', config=config)
    
    def get_kms_key_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the configured KMS key.
        
        Returns:
            KMS key information or None if not configured
        """
        if not self.kms_key_id:
            return None
        
        try:
            kms_client = self.get_kms_client()
            response = kms_client.describe_key(KeyId=self.kms_key_id)
            return {
                'key_id': response['KeyMetadata']['KeyId'],
                'key_arn': response['KeyMetadata']['Arn'],
                'description': response['KeyMetadata'].get('Description', ''),
                'key_state': response['KeyMetadata']['KeyState'],
                'key_usage': response['KeyMetadata']['KeyUsage'],
                'creation_date': response['KeyMetadata']['CreationDate'].isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to get KMS key info: {e}")
            return None
    
    def get_config(self) -> Dict[str, Any]:
        """
        Get configuration as dictionary.
        
        Returns:
            Configuration dictionary
        """
        return {
            'region': self.region,
            'access_key_id': self.access_key_id,
            'secret_access_key': '***' if self.secret_access_key else None,
            'session_token': '***' if self.session_token else None,
            'profile_name': self.profile_name,
            'kms_key_id': self.kms_key_id
        }
    
    @classmethod
    def from_env(cls) -> 'AWSConfig':
        """
        Create AWS config from environment variables.
        
        Returns:
            AWSConfig instance
        """
        return cls()
    
    @classmethod
    def from_profile(cls, profile_name: str, region: Optional[str] = None) -> 'AWSConfig':
        """
        Create AWS config from named profile.
        
        Args:
            profile_name: AWS profile name
            region: AWS region
            
        Returns:
            AWSConfig instance
        """
        return cls(profile_name=profile_name, region=region) 
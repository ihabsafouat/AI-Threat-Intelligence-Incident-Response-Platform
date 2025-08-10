"""
AWS Secrets Manager Integration
Provides secure storage and retrieval of API keys and sensitive configuration.
"""

import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


class SecretsManager:
    """AWS Secrets Manager client for secure API key management"""
    
    def __init__(self, region_name: str = 'us-east-1'):
        self.client = boto3.client('secretsmanager', region_name=region_name)
        self.cache = {}  # Simple in-memory cache
    
    def store_secret(self, secret_name: str, secret_value: Dict[str, Any]) -> bool:
        """Store a secret in AWS Secrets Manager"""
        try:
            # Convert dict to JSON string
            secret_string = json.dumps(secret_value)
            
            # Check if secret already exists
            try:
                self.client.describe_secret(SecretId=secret_name)
                # Secret exists, update it
                self.client.update_secret(
                    SecretId=secret_name,
                    SecretString=secret_string
                )
                logger.info(f"Updated existing secret: {secret_name}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    # Secret doesn't exist, create it
                    self.client.create_secret(
                        Name=secret_name,
                        SecretString=secret_string,
                        Description=f"API keys for {secret_name}",
                        Tags=[
                            {
                                'Key': 'Environment',
                                'Value': 'production'
                            },
                            {
                                'Key': 'Service',
                                'Value': 'threat-intelligence'
                            }
                        ]
                    )
                    logger.info(f"Created new secret: {secret_name}")
                else:
                    raise
            
            # Clear cache for this secret
            self.cache.pop(secret_name, None)
            return True
            
        except ClientError as e:
            logger.error(f"Failed to store secret {secret_name}: {e}")
            return False
        except NoCredentialsError:
            logger.error("AWS credentials not found")
            return False
    
    def get_secret(self, secret_name: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """Retrieve a secret from AWS Secrets Manager"""
        try:
            # Check cache first
            if use_cache and secret_name in self.cache:
                return self.cache[secret_name]
            
            # Get secret from AWS
            response = self.client.get_secret_value(SecretId=secret_name)
            
            if 'SecretString' in response:
                secret_value = json.loads(response['SecretString'])
                
                # Cache the secret
                if use_cache:
                    self.cache[secret_name] = secret_value
                
                logger.info(f"Retrieved secret: {secret_name}")
                return secret_value
            else:
                logger.error(f"Secret {secret_name} not found or is binary")
                return None
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.error(f"Secret {secret_name} not found")
            else:
                logger.error(f"Failed to retrieve secret {secret_name}: {e}")
            return None
        except NoCredentialsError:
            logger.error("AWS credentials not found")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse secret {secret_name}: {e}")
            return None
    
    def delete_secret(self, secret_name: str, force_delete: bool = False) -> bool:
        """Delete a secret from AWS Secrets Manager"""
        try:
            if force_delete:
                # Force delete immediately
                self.client.delete_secret(
                    SecretId=secret_name,
                    ForceDeleteWithoutRecovery=True
                )
            else:
                # Schedule deletion (7 days recovery window)
                self.client.delete_secret(SecretId=secret_name)
            
            # Remove from cache
            self.cache.pop(secret_name, None)
            logger.info(f"Deleted secret: {secret_name}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to delete secret {secret_name}: {e}")
            return False
        except NoCredentialsError:
            logger.error("AWS credentials not found")
            return False
    
    def list_secrets(self, filters: Optional[Dict[str, Any]] = None) -> list:
        """List all secrets with optional filtering"""
        try:
            kwargs = {}
            if filters:
                kwargs['Filters'] = filters
            
            response = self.client.list_secrets(**kwargs)
            secrets = response['SecretList']
            
            # Handle pagination
            while 'NextToken' in response:
                response = self.client.list_secrets(
                    NextToken=response['NextToken'],
                    **kwargs
                )
                secrets.extend(response['SecretList'])
            
            return secrets
            
        except ClientError as e:
            logger.error(f"Failed to list secrets: {e}")
            return []
        except NoCredentialsError:
            logger.error("AWS credentials not found")
            return []
    
    def rotate_secret(self, secret_name: str) -> bool:
        """Rotate a secret (requires custom rotation Lambda)"""
        try:
            self.client.rotate_secret(SecretId=secret_name)
            logger.info(f"Initiated rotation for secret: {secret_name}")
            return True
        except ClientError as e:
            logger.error(f"Failed to rotate secret {secret_name}: {e}")
            return False
        except NoCredentialsError:
            logger.error("AWS credentials not found")
            return False
    
    def get_secret_metadata(self, secret_name: str) -> Optional[Dict[str, Any]]:
        """Get metadata about a secret"""
        try:
            response = self.client.describe_secret(SecretId=secret_name)
            return {
                'name': response['Name'],
                'arn': response['ARN'],
                'description': response.get('Description', ''),
                'created_date': response.get('CreatedDate'),
                'last_modified_date': response.get('LastModifiedDate'),
                'last_rotated_date': response.get('LastRotatedDate'),
                'tags': response.get('Tags', [])
            }
        except ClientError as e:
            logger.error(f"Failed to get metadata for secret {secret_name}: {e}")
            return None
        except NoCredentialsError:
            logger.error("AWS credentials not found")
            return None


class APIKeyManager:
    """Manages API keys for threat intelligence services"""
    
    def __init__(self):
        self.secrets_manager = SecretsManager()
        self.secret_prefix = "threat-intelligence"
    
    def store_api_key(self, service_name: str, api_key: str, additional_data: Optional[Dict[str, Any]] = None) -> bool:
        """Store API key for a specific service"""
        secret_name = f"{self.secret_prefix}/{service_name}"
        
        secret_data = {
            'api_key': api_key,
            'service': service_name,
            'created_at': datetime.utcnow().isoformat(),
            'last_updated': datetime.utcnow().isoformat()
        }
        
        if additional_data:
            secret_data.update(additional_data)
        
        return self.secrets_manager.store_secret(secret_name, secret_data)
    
    def get_api_key(self, service_name: str) -> Optional[str]:
        """Get API key for a specific service"""
        secret_name = f"{self.secret_prefix}/{service_name}"
        secret_data = self.secrets_manager.get_secret(secret_name)
        
        if secret_data:
            return secret_data.get('api_key')
        return None
    
    def get_service_config(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get full service configuration including API key"""
        secret_name = f"{self.secret_prefix}/{service_name}"
        return self.secrets_manager.get_secret(secret_name)
    
    def update_api_key(self, service_name: str, new_api_key: str) -> bool:
        """Update API key for a specific service"""
        # Get existing configuration
        existing_config = self.get_service_config(service_name)
        if not existing_config:
            return False
        
        # Update API key and timestamp
        existing_config['api_key'] = new_api_key
        existing_config['last_updated'] = datetime.utcnow().isoformat()
        
        # Store updated configuration
        secret_name = f"{self.secret_prefix}/{service_name}"
        return self.secrets_manager.store_secret(secret_name, existing_config)
    
    def delete_api_key(self, service_name: str, force_delete: bool = False) -> bool:
        """Delete API key for a specific service"""
        secret_name = f"{self.secret_prefix}/{service_name}"
        return self.secrets_manager.delete_secret(secret_name, force_delete)
    
    def list_services(self) -> list:
        """List all configured services"""
        filters = [
            {
                'Key': 'name',
                'Values': [self.secret_prefix]
            }
        ]
        
        secrets = self.secrets_manager.list_secrets(filters)
        services = []
        
        for secret in secrets:
            service_name = secret['Name'].replace(f"{self.secret_prefix}/", "")
            services.append({
                'name': service_name,
                'arn': secret['ARN'],
                'created_date': secret.get('CreatedDate'),
                'last_modified_date': secret.get('LastModifiedDate')
            })
        
        return services
    
    def rotate_api_key(self, service_name: str) -> bool:
        """Rotate API key for a specific service"""
        secret_name = f"{self.secret_prefix}/{service_name}"
        return self.secrets_manager.rotate_secret(secret_name)


# Predefined service configurations
SERVICE_CONFIGS = {
    'nvd': {
        'description': 'National Vulnerability Database API',
        'rate_limit': '5 requests per 30 seconds',
        'base_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0/'
    },
    'virustotal': {
        'description': 'VirusTotal API',
        'rate_limit': '4 requests per minute (public), 500 requests per minute (private)',
        'base_url': 'https://www.virustotal.com/vtapi/v2/'
    },
    'shodan': {
        'description': 'Shodan API',
        'rate_limit': '1 request per second (free), 10 requests per second (paid)',
        'base_url': 'https://api.shodan.io/'
    },
    'mitre': {
        'description': 'MITRE ATT&CK API',
        'rate_limit': '10 requests per minute',
        'base_url': 'https://attack.mitre.org/api/'
    },
    'alienvault': {
        'description': 'AlienVault OTX API',
        'rate_limit': '100 requests per minute',
        'base_url': 'https://otx.alienvault.com/api/v1/'
    }
}


def initialize_api_keys():
    """Initialize API keys for all services"""
    api_manager = APIKeyManager()
    
    for service_name, config in SERVICE_CONFIGS.items():
        # Check if service is already configured
        existing_config = api_manager.get_service_config(service_name)
        if not existing_config:
            logger.info(f"Service {service_name} not configured. Please add API key.")
            logger.info(f"Configuration: {config}")
    
    return api_manager 
"""
AWS KMS Service Module

Handles AWS Key Management Service (KMS) operations for encryption key management.
"""

import os
import json
import logging
from typing import Optional, Dict, Any, List
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from .config import AWSConfig

logger = logging.getLogger(__name__)


class KMSService:
    """AWS KMS Service for encryption key management"""
    
    def __init__(self, config: AWSConfig):
        """
        Initialize KMS service.
        
        Args:
            config: AWS configuration
        """
        self.config = config
        self.kms_client = config.get_kms_client()
    
    def create_key(
        self,
        description: str,
        key_usage: str = 'ENCRYPT_DECRYPT',
        key_spec: str = 'SYMMETRIC_DEFAULT',
        tags: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Create a new KMS key.
        
        Args:
            description: Key description
            key_usage: Key usage (ENCRYPT_DECRYPT or SIGN_VERIFY)
            key_spec: Key specification
            tags: Optional tags for the key
            
        Returns:
            Key creation result dictionary
        """
        try:
            create_key_params = {
                'Description': description,
                'KeyUsage': key_usage,
                'KeySpec': key_spec
            }
            
            if tags:
                create_key_params['Tags'] = tags
            
            response = self.kms_client.create_key(**create_key_params)
            
            key_id = response['KeyMetadata']['KeyId']
            key_arn = response['KeyMetadata']['Arn']
            
            logger.info(f"Successfully created KMS key: {key_id}")
            
            return {
                'success': True,
                'key_id': key_id,
                'key_arn': key_arn,
                'description': description,
                'key_usage': key_usage,
                'key_spec': key_spec
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to create KMS key: {e}")
            return {'success': False, 'error': str(e)}
    
    def create_alias(self, key_id: str, alias_name: str) -> Dict[str, Any]:
        """
        Create an alias for a KMS key.
        
        Args:
            key_id: KMS key ID
            alias_name: Alias name
            
        Returns:
            Alias creation result dictionary
        """
        try:
            self.kms_client.create_alias(
                AliasName=alias_name,
                TargetKeyId=key_id
            )
            
            logger.info(f"Successfully created alias '{alias_name}' for key {key_id}")
            
            return {
                'success': True,
                'alias_name': alias_name,
                'key_id': key_id
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to create KMS alias: {e}")
            return {'success': False, 'error': str(e)}
    
    def describe_key(self, key_id: str) -> Dict[str, Any]:
        """
        Get information about a KMS key.
        
        Args:
            key_id: KMS key ID or alias
            
        Returns:
            Key information dictionary
        """
        try:
            response = self.kms_client.describe_key(KeyId=key_id)
            key_metadata = response['KeyMetadata']
            
            return {
                'success': True,
                'key_id': key_metadata['KeyId'],
                'key_arn': key_metadata['Arn'],
                'description': key_metadata.get('Description', ''),
                'key_state': key_metadata['KeyState'],
                'key_usage': key_metadata['KeyUsage'],
                'key_spec': key_metadata.get('KeySpec', ''),
                'creation_date': key_metadata['CreationDate'].isoformat(),
                'enabled': key_metadata['Enabled']
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to describe KMS key: {e}")
            return {'success': False, 'error': str(e)}
    
    def list_keys(self, limit: int = 100) -> Dict[str, Any]:
        """
        List KMS keys.
        
        Args:
            limit: Maximum number of keys to return
            
        Returns:
            List of KMS keys
        """
        try:
            response = self.kms_client.list_keys(Limit=limit)
            
            keys = []
            for key in response['Keys']:
                key_info = self.describe_key(key['KeyId'])
                if key_info['success']:
                    keys.append(key_info)
            
            return {
                'success': True,
                'keys': keys,
                'count': len(keys)
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to list KMS keys: {e}")
            return {'success': False, 'error': str(e)}
    
    def list_aliases(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        List KMS aliases.
        
        Args:
            key_id: Optional key ID to filter aliases
            
        Returns:
            List of KMS aliases
        """
        try:
            params = {}
            if key_id:
                params['KeyId'] = key_id
            
            response = self.kms_client.list_aliases(**params)
            
            aliases = []
            for alias in response['Aliases']:
                aliases.append({
                    'alias_name': alias['AliasName'],
                    'alias_arn': alias['AliasArn'],
                    'target_key_id': alias.get('TargetKeyId', ''),
                    'creation_date': alias['CreationDate'].isoformat()
                })
            
            return {
                'success': True,
                'aliases': aliases,
                'count': len(aliases)
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to list KMS aliases: {e}")
            return {'success': False, 'error': str(e)}
    
    def enable_key(self, key_id: str) -> Dict[str, Any]:
        """
        Enable a KMS key.
        
        Args:
            key_id: KMS key ID
            
        Returns:
            Enable result dictionary
        """
        try:
            self.kms_client.enable_key(KeyId=key_id)
            
            logger.info(f"Successfully enabled KMS key: {key_id}")
            
            return {
                'success': True,
                'key_id': key_id,
                'action': 'enabled'
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to enable KMS key: {e}")
            return {'success': False, 'error': str(e)}
    
    def disable_key(self, key_id: str) -> Dict[str, Any]:
        """
        Disable a KMS key.
        
        Args:
            key_id: KMS key ID
            
        Returns:
            Disable result dictionary
        """
        try:
            self.kms_client.disable_key(KeyId=key_id)
            
            logger.info(f"Successfully disabled KMS key: {key_id}")
            
            return {
                'success': True,
                'key_id': key_id,
                'action': 'disabled'
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to disable KMS key: {e}")
            return {'success': False, 'error': str(e)}
    
    def schedule_key_deletion(self, key_id: str, pending_window_in_days: int = 7) -> Dict[str, Any]:
        """
        Schedule a KMS key for deletion.
        
        Args:
            key_id: KMS key ID
            pending_window_in_days: Days to wait before deletion
            
        Returns:
            Deletion schedule result dictionary
        """
        try:
            response = self.kms_client.schedule_key_deletion(
                KeyId=key_id,
                PendingWindowInDays=pending_window_in_days
            )
            
            logger.info(f"Scheduled KMS key {key_id} for deletion in {pending_window_in_days} days")
            
            return {
                'success': True,
                'key_id': key_id,
                'deletion_date': response['DeletionDate'].isoformat(),
                'pending_window_in_days': pending_window_in_days
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to schedule KMS key deletion: {e}")
            return {'success': False, 'error': str(e)}
    
    def cancel_key_deletion(self, key_id: str) -> Dict[str, Any]:
        """
        Cancel scheduled deletion of a KMS key.
        
        Args:
            key_id: KMS key ID
            
        Returns:
            Cancellation result dictionary
        """
        try:
            self.kms_client.cancel_key_deletion(KeyId=key_id)
            
            logger.info(f"Cancelled deletion of KMS key: {key_id}")
            
            return {
                'success': True,
                'key_id': key_id,
                'action': 'deletion_cancelled'
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to cancel KMS key deletion: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_key_policy(self, key_id: str, policy_name: str = 'default') -> Dict[str, Any]:
        """
        Get the key policy for a KMS key.
        
        Args:
            key_id: KMS key ID
            policy_name: Policy name (default: 'default')
            
        Returns:
            Key policy dictionary
        """
        try:
            response = self.kms_client.get_key_policy(
                KeyId=key_id,
                PolicyName=policy_name
            )
            
            policy = json.loads(response['Policy'])
            
            return {
                'success': True,
                'key_id': key_id,
                'policy_name': policy_name,
                'policy': policy
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to get KMS key policy: {e}")
            return {'success': False, 'error': str(e)}
    
    def put_key_policy(self, key_id: str, policy: Dict[str, Any], policy_name: str = 'default') -> Dict[str, Any]:
        """
        Update the key policy for a KMS key.
        
        Args:
            key_id: KMS key ID
            policy: Key policy document
            policy_name: Policy name (default: 'default')
            
        Returns:
            Policy update result dictionary
        """
        try:
            policy_json = json.dumps(policy, indent=2)
            
            self.kms_client.put_key_policy(
                KeyId=key_id,
                PolicyName=policy_name,
                Policy=policy_json
            )
            
            logger.info(f"Successfully updated policy for KMS key: {key_id}")
            
            return {
                'success': True,
                'key_id': key_id,
                'policy_name': policy_name
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to update KMS key policy: {e}")
            return {'success': False, 'error': str(e)}
    
    def encrypt_data(self, key_id: str, plaintext: bytes) -> Dict[str, Any]:
        """
        Encrypt data using a KMS key.
        
        Args:
            key_id: KMS key ID
            plaintext: Data to encrypt
            
        Returns:
            Encryption result dictionary
        """
        try:
            response = self.kms_client.encrypt(
                KeyId=key_id,
                Plaintext=plaintext
            )
            
            return {
                'success': True,
                'ciphertext': response['CiphertextBlob'],
                'key_id': response['KeyId']
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to encrypt data: {e}")
            return {'success': False, 'error': str(e)}
    
    def decrypt_data(self, ciphertext: bytes, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Decrypt data using a KMS key.
        
        Args:
            ciphertext: Encrypted data
            key_id: Optional KMS key ID (if not specified, will be extracted from ciphertext)
            
        Returns:
            Decryption result dictionary
        """
        try:
            params = {'CiphertextBlob': ciphertext}
            if key_id:
                params['KeyId'] = key_id
            
            response = self.kms_client.decrypt(**params)
            
            return {
                'success': True,
                'plaintext': response['Plaintext'],
                'key_id': response['KeyId']
            }
            
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to decrypt data: {e}")
            return {'success': False, 'error': str(e)} 
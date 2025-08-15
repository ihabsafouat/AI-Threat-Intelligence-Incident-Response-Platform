#!/usr/bin/env python3
"""
Test KMS Encryption Implementation

This script tests the KMS encryption functionality for S3 file storage.
"""

import os
import sys
import json
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone
from pathlib import Path

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.aws import (
    AWSConfig, S3Service, KMSService
)


class TestKMSEncryption(unittest.TestCase):
    """Test cases for KMS encryption functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = AWSConfig.from_env()
        self.kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
        self.bucket_name = "test-threat-intelligence-bucket"
        
        # Mock AWS clients
        self.mock_s3_client = Mock()
        self.mock_kms_client = Mock()
        
    def test_s3_service_kms_initialization(self):
        """Test S3Service initialization with KMS key."""
        with patch('app.services.aws.s3_service.boto3') as mock_boto3:
            mock_boto3.client.return_value = self.mock_s3_client
            mock_boto3.resource.return_value = Mock()
            
            s3_service = S3Service(
                self.config,
                bucket_name=self.bucket_name,
                kms_key_id=self.kms_key_id
            )
            
            self.assertEqual(s3_service.kms_key_id, self.kms_key_id)
            self.assertEqual(s3_service.bucket_name, self.bucket_name)
    
    def test_s3_service_fallback_to_aes256(self):
        """Test S3Service falls back to AES256 when no KMS key is provided."""
        with patch('app.services.aws.s3_service.boto3') as mock_boto3:
            mock_boto3.client.return_value = self.mock_s3_client
            mock_boto3.resource.return_value = Mock()
            
            s3_service = S3Service(
                self.config,
                bucket_name=self.bucket_name
            )
            
            self.assertIsNone(s3_service.kms_key_id)
    
    def test_upload_file_with_kms_encryption(self):
        """Test file upload with KMS encryption."""
        with patch('app.services.aws.s3_service.boto3') as mock_boto3:
            mock_boto3.client.return_value = self.mock_s3_client
            mock_boto3.resource.return_value = Mock()
            
            s3_service = S3Service(
                self.config,
                bucket_name=self.bucket_name,
                kms_key_id=self.kms_key_id
            )
            
            # Create a temporary test file
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write('{"test": "data"}')
                temp_file_path = temp_file.name
            
            try:
                # Test upload with KMS encryption
                result = s3_service.upload_file(
                    file_path=temp_file_path,
                    s3_key="test/encrypted-file.json",
                    encrypt=True
                )
                
                # Verify the upload was called with KMS parameters
                self.mock_s3_client.upload_file.assert_called_once()
                call_args = self.mock_s3_client.upload_file.call_args
                
                # Check that KMS encryption parameters were passed
                extra_args = call_args[1]['ExtraArgs']
                self.assertEqual(extra_args['ServerSideEncryption'], 'aws:kms')
                self.assertEqual(extra_args['SSEKMSKeyId'], self.kms_key_id)
                
            finally:
                # Clean up
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
    
    def test_upload_file_with_aes256_fallback(self):
        """Test file upload falls back to AES256 when no KMS key."""
        with patch('app.services.aws.s3_service.boto3') as mock_boto3:
            mock_boto3.client.return_value = self.mock_s3_client
            mock_boto3.resource.return_value = Mock()
            
            s3_service = S3Service(
                self.config,
                bucket_name=self.bucket_name
            )
            
            # Create a temporary test file
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write('{"test": "data"}')
                temp_file_path = temp_file.name
            
            try:
                # Test upload with AES256 encryption
                result = s3_service.upload_file(
                    file_path=temp_file_path,
                    s3_key="test/aes256-file.json",
                    encrypt=True
                )
                
                # Verify the upload was called with AES256 parameters
                self.mock_s3_client.upload_file.assert_called_once()
                call_args = self.mock_s3_client.upload_file.call_args
                
                # Check that AES256 encryption parameters were passed
                extra_args = call_args[1]['ExtraArgs']
                self.assertEqual(extra_args['ServerSideEncryption'], 'AES256')
                
            finally:
                # Clean up
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
    
    def test_upload_threat_data_with_kms(self):
        """Test threat data upload with KMS encryption."""
        with patch('app.services.aws.s3_service.boto3') as mock_boto3:
            mock_boto3.client.return_value = self.mock_s3_client
            mock_boto3.resource.return_value = Mock()
            
            s3_service = S3Service(
                self.config,
                bucket_name=self.bucket_name,
                kms_key_id=self.kms_key_id
            )
            
            threat_data = {
                "threat_id": "TEST-001",
                "threat_type": "malware",
                "severity": "high",
                "indicators": ["192.168.1.100"]
            }
            
            # Test threat data upload
            result = s3_service.upload_threat_data(
                threat_data=threat_data,
                threat_id="TEST-001",
                data_type="malware"
            )
            
            # Verify put_object was called with KMS parameters
            self.mock_s3_client.put_object.assert_called_once()
            call_args = self.mock_s3_client.put_object.call_args[1]
            
            self.assertEqual(call_args['ServerSideEncryption'], 'aws:kms')
            self.assertEqual(call_args['SSEKMSKeyId'], self.kms_key_id)
    
    def test_kms_service_creation(self):
        """Test KMSService initialization."""
        with patch('app.services.aws.kms_service.boto3') as mock_boto3:
            mock_boto3.client.return_value = self.mock_kms_client
            
            kms_service = KMSService(self.config)
            
            self.assertIsNotNone(kms_service.kms_client)
    
    def test_kms_key_creation(self):
        """Test KMS key creation."""
        with patch('app.services.aws.kms_service.boto3') as mock_boto3:
            mock_boto3.client.return_value = self.mock_kms_client
            
            # Mock successful key creation response
            mock_response = {
                'KeyMetadata': {
                    'KeyId': 'test-key-id',
                    'Arn': 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
                    'Description': 'Test key',
                    'KeyState': 'Enabled',
                    'KeyUsage': 'ENCRYPT_DECRYPT'
                }
            }
            self.mock_kms_client.create_key.return_value = mock_response
            
            kms_service = KMSService(self.config)
            
            result = kms_service.create_key(
                description="Test encryption key",
                key_usage="ENCRYPT_DECRYPT"
            )
            
            self.assertTrue(result['success'])
            self.assertEqual(result['key_id'], 'test-key-id')
            self.assertEqual(result['description'], 'Test encryption key')
    
    def test_kms_key_description(self):
        """Test KMS key description."""
        with patch('app.services.aws.kms_service.boto3') as mock_boto3:
            mock_boto3.client.return_value = self.mock_kms_client
            
            # Mock successful key description response
            mock_response = {
                'KeyMetadata': {
                    'KeyId': 'test-key-id',
                    'Arn': 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
                    'Description': 'Test key',
                    'KeyState': 'Enabled',
                    'KeyUsage': 'ENCRYPT_DECRYPT',
                    'KeySpec': 'SYMMETRIC_DEFAULT',
                    'CreationDate': datetime.now(timezone.utc),
                    'Enabled': True
                }
            }
            self.mock_kms_client.describe_key.return_value = mock_response
            
            kms_service = KMSService(self.config)
            
            result = kms_service.describe_key('test-key-id')
            
            self.assertTrue(result['success'])
            self.assertEqual(result['key_id'], 'test-key-id')
            self.assertEqual(result['key_state'], 'Enabled')
    
    def test_kms_data_encryption(self):
        """Test KMS data encryption and decryption."""
        with patch('app.services.aws.kms_service.boto3') as mock_boto3:
            mock_boto3.client.return_value = self.mock_kms_client
            
            test_data = b"This is test data to encrypt"
            
            # Mock encryption response
            mock_encrypt_response = {
                'CiphertextBlob': b'encrypted-data-blob',
                'KeyId': 'test-key-id'
            }
            self.mock_kms_client.encrypt.return_value = mock_encrypt_response
            
            # Mock decryption response
            mock_decrypt_response = {
                'Plaintext': test_data,
                'KeyId': 'test-key-id'
            }
            self.mock_kms_client.decrypt.return_value = mock_decrypt_response
            
            kms_service = KMSService(self.config)
            
            # Test encryption
            encrypt_result = kms_service.encrypt_data('test-key-id', test_data)
            
            self.assertTrue(encrypt_result['success'])
            self.assertEqual(encrypt_result['ciphertext'], b'encrypted-data-blob')
            
            # Test decryption
            decrypt_result = kms_service.decrypt_data(b'encrypted-data-blob')
            
            self.assertTrue(decrypt_result['success'])
            self.assertEqual(decrypt_result['plaintext'], test_data)
    
    def test_aws_config_kms_support(self):
        """Test AWSConfig KMS support."""
        config = AWSConfig(kms_key_id=self.kms_key_id)
        
        self.assertEqual(config.kms_key_id, self.kms_key_id)
        
        # Test KMS client creation
        with patch('app.services.aws.config.boto3') as mock_boto3:
            mock_session = Mock()
            mock_session.client.return_value = self.mock_kms_client
            mock_boto3.Session.return_value = mock_session
            
            kms_client = config.get_kms_client()
            
            self.assertIsNotNone(kms_client)
    
    def test_aws_config_kms_key_info(self):
        """Test AWSConfig KMS key information retrieval."""
        config = AWSConfig(kms_key_id=self.kms_key_id)
        
        with patch('app.services.aws.config.boto3') as mock_boto3:
            mock_session = Mock()
            mock_kms_client = Mock()
            
            # Mock successful key description response
            mock_response = {
                'KeyMetadata': {
                    'KeyId': 'test-key-id',
                    'Arn': 'arn:aws:kms:us-east-1:123456789012:key/test-key-id',
                    'Description': 'Test key',
                    'KeyState': 'Enabled',
                    'KeyUsage': 'ENCRYPT_DECRYPT',
                    'CreationDate': datetime.now(timezone.utc)
                }
            }
            mock_kms_client.describe_key.return_value = mock_response
            mock_session.client.return_value = mock_kms_client
            mock_boto3.Session.return_value = mock_session
            
            key_info = config.get_kms_key_info()
            
            self.assertIsNotNone(key_info)
            self.assertEqual(key_info['key_id'], 'test-key-id')
            self.assertEqual(key_info['key_state'], 'Enabled')


class TestKMSEncryptionIntegration(unittest.TestCase):
    """Integration tests for KMS encryption (requires AWS credentials)."""
    
    @unittest.skipUnless(
        os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('KMS_KEY_ID'),
        "AWS credentials and KMS key ID required for integration tests"
    )
    def test_real_kms_operations(self):
        """Test real KMS operations with AWS."""
        config = AWSConfig.from_env()
        kms_service = KMSService(config)
        
        # Test key information retrieval
        kms_key_id = os.getenv('KMS_KEY_ID')
        key_info = kms_service.describe_key(kms_key_id)
        
        self.assertTrue(key_info['success'])
        self.assertEqual(key_info['key_id'], kms_key_id.split('/')[-1])
    
    @unittest.skipUnless(
        os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('S3_BUCKET') and os.getenv('KMS_KEY_ID'),
        "AWS credentials, S3 bucket, and KMS key ID required for integration tests"
    )
    def test_real_s3_encryption(self):
        """Test real S3 encryption with KMS."""
        config = AWSConfig.from_env()
        s3_service = S3Service(
            config,
            bucket_name=os.getenv('S3_BUCKET'),
            kms_key_id=os.getenv('KMS_KEY_ID')
        )
        
        # Create test data
        test_data = {
            "test_id": "integration-test",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": "This is test data for KMS encryption"
        }
        
        # Test threat data upload
        result = s3_service.upload_threat_data(
            threat_data=test_data,
            threat_id="integration-test",
            data_type="test"
        )
        
        self.assertTrue(result['success'])
        self.assertEqual(result['encryption'], 'KMS')
        self.assertEqual(result['kms_key_id'], os.getenv('KMS_KEY_ID'))


def run_tests():
    """Run all KMS encryption tests."""
    print("🔐 Running KMS Encryption Tests")
    print("=" * 50)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add unit tests
    test_suite.addTest(unittest.makeSuite(TestKMSEncryption))
    
    # Add integration tests if credentials are available
    if (os.getenv('AWS_ACCESS_KEY_ID') and 
        os.getenv('S3_BUCKET') and 
        os.getenv('KMS_KEY_ID')):
        test_suite.addTest(unittest.makeSuite(TestKMSEncryptionIntegration))
        print("✅ Integration tests enabled (AWS credentials found)")
    else:
        print("⚠️  Integration tests skipped (AWS credentials not found)")
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ Failures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\n❌ Errors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    if not result.failures and not result.errors:
        print("✅ All tests passed!")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1) 
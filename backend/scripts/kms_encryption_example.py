#!/usr/bin/env python3
"""
KMS Encryption Example for S3 File Storage

This script demonstrates how to use AWS KMS encryption for S3 file storage
in the Threat Intelligence Platform.
"""

import os
import sys
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.aws import (
    AWSConfig, S3Service, KMSService
)


def setup_kms_key():
    """Setup and configure a KMS key for S3 encryption."""
    print("=== KMS Key Setup ===")
    
    config = AWSConfig.from_env()
    kms_service = KMSService(config)
    
    # Check if KMS key ID is provided via environment
    kms_key_id = os.getenv('KMS_KEY_ID')
    
    if kms_key_id:
        print(f"Using existing KMS key: {kms_key_id}")
        
        # Get key information
        key_info = kms_service.describe_key(kms_key_id)
        if key_info['success']:
            print(f"✅ Key Information:")
            print(f"   Key ID: {key_info['key_id']}")
            print(f"   Key ARN: {key_info['key_arn']}")
            print(f"   Description: {key_info['description']}")
            print(f"   State: {key_info['key_state']}")
            print(f"   Usage: {key_info['key_usage']}")
            print(f"   Enabled: {key_info['enabled']}")
        else:
            print(f"❌ Failed to get key info: {key_info['error']}")
            return None
    else:
        print("No KMS key ID provided. Creating a new key...")
        
        # Create a new KMS key
        key_result = kms_service.create_key(
            description="S3 encryption key for threat intelligence platform",
            key_usage="ENCRYPT_DECRYPT",
            key_spec="SYMMETRIC_DEFAULT",
            tags=[
                {"TagKey": "Environment", "TagValue": "Production"},
                {"TagKey": "Purpose", "TagValue": "S3Encryption"},
                {"TagKey": "Service", "TagValue": "ThreatIntelligence"}
            ]
        )
        
        if key_result['success']:
            kms_key_id = key_result['key_id']
            print(f"✅ Created new KMS key: {kms_key_id}")
            
            # Create an alias for easier reference
            alias_result = kms_service.create_alias(
                kms_key_id, 
                "alias/threat-intelligence-s3-encryption"
            )
            
            if alias_result['success']:
                print(f"✅ Created alias: {alias_result['alias_name']}")
            
            return kms_key_id
        else:
            print(f"❌ Failed to create KMS key: {key_result['error']}")
            return None
    
    return kms_key_id


def demonstrate_s3_encryption(kms_key_id: str):
    """Demonstrate S3 encryption with KMS."""
    print("\n=== S3 Encryption Demonstration ===")
    
    config = AWSConfig.from_env()
    
    # Initialize S3 service with KMS encryption
    s3_service = S3Service(
        config,
        bucket_name=os.getenv('S3_BUCKET', 'threat-intelligence-bucket'),
        kms_key_id=kms_key_id
    )
    
    # Create sample threat data
    threat_data = {
        "threat_id": "THREAT-KMS-001",
        "threat_type": "advanced_persistent_threat",
        "severity": "critical",
        "description": "APT group targeting financial institutions",
        "indicators": [
            "192.168.1.100",
            "malicious-domain.com",
            "abc123def456",
            "suspicious-process.exe"
        ],
        "source": "threat_intelligence_feed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "apt_group": "APT29",
            "target_sector": "financial",
            "attack_vectors": ["phishing", "watering_hole", "supply_chain"],
            "malware_families": ["TrickBot", "Emotet"],
            "affected_countries": ["US", "UK", "DE"],
            "estimated_damage": "$50M"
        },
        "encryption_info": {
            "encryption_type": "KMS",
            "kms_key_id": kms_key_id,
            "encryption_timestamp": datetime.now(timezone.utc).isoformat()
        }
    }
    
    print("1. Uploading threat data with KMS encryption...")
    
    # Upload threat data with KMS encryption
    upload_result = s3_service.upload_threat_data(
        threat_data=threat_data,
        threat_id="THREAT-KMS-001",
        data_type="apt",
        compress=True
    )
    
    if upload_result['success']:
        print(f"✅ Successfully uploaded with KMS encryption:")
        print(f"   S3 Key: {upload_result['key']}")
        print(f"   Encryption: {upload_result['encryption']}")
        print(f"   KMS Key ID: {upload_result['kms_key_id']}")
        print(f"   Size: {upload_result['size']} bytes")
        print(f"   Compressed: {upload_result['compressed']}")
        
        # Retrieve the data to verify encryption/decryption
        print("\n2. Retrieving encrypted data...")
        retrieve_result = s3_service.get_threat_data("THREAT-KMS-001", "apt")
        
        if retrieve_result['success']:
            retrieved_data = retrieve_result['threat_data']
            print(f"✅ Successfully retrieved and decrypted data:")
            print(f"   Threat ID: {retrieved_data['threat_id']}")
            print(f"   Threat Type: {retrieved_data['threat_type']}")
            print(f"   Severity: {retrieved_data['severity']}")
            print(f"   Indicators Count: {len(retrieved_data['indicators'])}")
            
            # Verify data integrity
            if retrieved_data['threat_id'] == threat_data['threat_id']:
                print("✅ Data integrity verified - retrieved data matches original")
            else:
                print("❌ Data integrity check failed")
        else:
            print(f"❌ Failed to retrieve data: {retrieve_result['error']}")
    else:
        print(f"❌ Failed to upload data: {upload_result['error']}")


def demonstrate_file_encryption(kms_key_id: str):
    """Demonstrate file encryption with KMS."""
    print("\n=== File Encryption Demonstration ===")
    
    config = AWSConfig.from_env()
    s3_service = S3Service(
        config,
        bucket_name=os.getenv('S3_BUCKET', 'threat-intelligence-bucket'),
        kms_key_id=kms_key_id
    )
    
    # Create a temporary file with sensitive data
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
        sensitive_data = {
            "file_type": "sensitive_configuration",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "configuration": {
                "api_keys": ["sk-1234567890abcdef", "sk-fedcba0987654321"],
                "database_credentials": {
                    "host": "sensitive-db.example.com",
                    "port": 5432,
                    "database": "threat_intelligence"
                },
                "encryption_keys": ["key1", "key2", "key3"],
                "access_tokens": ["token1", "token2", "token3"]
            },
            "metadata": {
                "owner": "security_team",
                "classification": "confidential",
                "retention_period": "1_year"
            }
        }
        
        json.dump(sensitive_data, temp_file, indent=2)
        temp_file_path = temp_file.name
    
    try:
        print(f"1. Created temporary file: {temp_file_path}")
        
        # Upload file with KMS encryption
        print("2. Uploading sensitive file with KMS encryption...")
        upload_result = s3_service.upload_file(
            file_path=temp_file_path,
            s3_key="sensitive/config/encrypted_config.json",
            content_type="application/json",
            metadata={
                "file_type": "sensitive_configuration",
                "encryption": "KMS",
                "kms_key_id": kms_key_id,
                "upload_timestamp": datetime.now(timezone.utc).isoformat()
            },
            encrypt=True
        )
        
        if upload_result['success']:
            print(f"✅ Successfully uploaded sensitive file:")
            print(f"   S3 Key: {upload_result['key']}")
            print(f"   Encryption: {upload_result['encryption']}")
            print(f"   KMS Key ID: {upload_result['kms_key_id']}")
            print(f"   Size: {upload_result['size']} bytes")
            
            # Download and verify the file
            print("\n3. Downloading and verifying encrypted file...")
            download_path = temp_file_path.replace('.json', '_downloaded.json')
            download_result = s3_service.download_file(
                s3_key=upload_result['key'],
                local_path=download_path
            )
            
            if download_result['success']:
                print(f"✅ Successfully downloaded and decrypted file:")
                print(f"   Local Path: {download_result['local_path']}")
                print(f"   Size: {download_result['size']} bytes")
                
                # Verify file contents
                with open(download_path, 'r') as f:
                    downloaded_data = json.load(f)
                
                if downloaded_data['file_type'] == sensitive_data['file_type']:
                    print("✅ File content verification successful")
                else:
                    print("❌ File content verification failed")
                
                # Clean up downloaded file
                os.remove(download_path)
            else:
                print(f"❌ Failed to download file: {download_result['error']}")
        else:
            print(f"❌ Failed to upload file: {upload_result['error']}")
    
    finally:
        # Clean up temporary file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)


def demonstrate_kms_operations():
    """Demonstrate various KMS operations."""
    print("\n=== KMS Operations Demonstration ===")
    
    config = AWSConfig.from_env()
    kms_service = KMSService(config)
    
    # List existing keys
    print("1. Listing existing KMS keys...")
    keys_result = kms_service.list_keys(limit=10)
    
    if keys_result['success']:
        print(f"✅ Found {keys_result['count']} KMS keys:")
        for key in keys_result['keys']:
            print(f"   - {key['key_id']}: {key['description']} ({key['key_state']})")
    else:
        print(f"❌ Failed to list keys: {keys_result['error']}")
    
    # List aliases
    print("\n2. Listing KMS aliases...")
    aliases_result = kms_service.list_aliases()
    
    if aliases_result['success']:
        print(f"✅ Found {aliases_result['count']} KMS aliases:")
        for alias in aliases_result['aliases']:
            print(f"   - {alias['alias_name']} -> {alias['target_key_id']}")
    else:
        print(f"❌ Failed to list aliases: {aliases_result['error']}")
    
    # Demonstrate data encryption/decryption
    print("\n3. Demonstrating data encryption/decryption...")
    
    test_data = b"This is sensitive data that needs to be encrypted"
    kms_key_id = os.getenv('KMS_KEY_ID')
    
    if kms_key_id:
        # Encrypt data
        encrypt_result = kms_service.encrypt_data(kms_key_id, test_data)
        
        if encrypt_result['success']:
            print(f"✅ Successfully encrypted data:")
            print(f"   Original size: {len(test_data)} bytes")
            print(f"   Encrypted size: {len(encrypt_result['ciphertext'])} bytes")
            
            # Decrypt data
            decrypt_result = kms_service.decrypt_data(encrypt_result['ciphertext'])
            
            if decrypt_result['success']:
                decrypted_data = decrypt_result['plaintext']
                print(f"✅ Successfully decrypted data:")
                print(f"   Decrypted size: {len(decrypted_data)} bytes")
                
                if decrypted_data == test_data:
                    print("✅ Data integrity verified - decrypted data matches original")
                else:
                    print("❌ Data integrity check failed")
            else:
                print(f"❌ Failed to decrypt data: {decrypt_result['error']}")
        else:
            print(f"❌ Failed to encrypt data: {encrypt_result['error']}")
    else:
        print("❌ No KMS key ID available for encryption test")


def main():
    """Main function to run KMS encryption demonstrations."""
    print("🔐 KMS Encryption Example for S3 File Storage")
    print("=" * 60)
    
    # Setup KMS key
    kms_key_id = setup_kms_key()
    
    if not kms_key_id:
        print("❌ Cannot proceed without a valid KMS key")
        return
    
    # Demonstrate S3 encryption
    demonstrate_s3_encryption(kms_key_id)
    
    # Demonstrate file encryption
    demonstrate_file_encryption(kms_key_id)
    
    # Demonstrate KMS operations
    demonstrate_kms_operations()
    
    print("\n" + "=" * 60)
    print("✅ KMS Encryption demonstration completed successfully!")
    print("\nKey Benefits of KMS Encryption:")
    print("  🔐 Automatic key rotation and management")
    print("  🛡️  Hardware security module (HSM) protection")
    print("  📊 Detailed audit logs and compliance")
    print("  🔑 Centralized key management")
    print("  🚀 Seamless integration with AWS services")


if __name__ == "__main__":
    main() 
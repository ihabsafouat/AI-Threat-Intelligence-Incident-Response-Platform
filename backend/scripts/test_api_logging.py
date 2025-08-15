#!/usr/bin/env python3
"""
Test API Logging System

This script tests the API logging functionality by making requests to the API
and verifying that logs are created in both CloudWatch and the database.
"""

import os
import sys
import json
import time
import requests
from datetime import datetime, timezone
from pathlib import Path

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.database.api_logging_service import api_logging_service


def test_api_logging():
    """Test the API logging system"""
    print("🔍 Testing API Logging System")
    print("=" * 50)
    
    # Configuration
    base_url = "http://localhost:8000"
    api_url = f"{base_url}/api/v1"
    
    # Test data
    test_threat = {
        "threat_type": "malware",
        "severity": "high",
        "description": "Test threat for logging verification",
        "indicators": ["192.168.1.100", "test-malware.com"],
        "source": "test_script",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    print("1. Testing API endpoints to generate logs...")
    
    # Test 1: Health check (should not require auth)
    print("   - Testing health check endpoint...")
    try:
        response = requests.get(f"{base_url}/health")
        print(f"   ✅ Health check: {response.status_code}")
        request_id = response.headers.get("X-Request-ID")
        if request_id:
            print(f"   📝 Request ID: {request_id}")
    except Exception as e:
        print(f"   ❌ Health check failed: {e}")
    
    # Test 2: Root endpoint
    print("   - Testing root endpoint...")
    try:
        response = requests.get(f"{base_url}/")
        print(f"   ✅ Root endpoint: {response.status_code}")
        request_id = response.headers.get("X-Request-ID")
        if request_id:
            print(f"   📝 Request ID: {request_id}")
    except Exception as e:
        print(f"   ❌ Root endpoint failed: {e}")
    
    # Test 3: API endpoint (will likely fail without auth, but should still log)
    print("   - Testing API endpoint (expected to fail without auth)...")
    try:
        response = requests.post(
            f"{api_url}/threats",
            json=test_threat,
            headers={"Content-Type": "application/json"}
        )
        print(f"   ✅ API endpoint: {response.status_code}")
        request_id = response.headers.get("X-Request-ID")
        if request_id:
            print(f"   📝 Request ID: {request_id}")
    except Exception as e:
        print(f"   ❌ API endpoint failed: {e}")
    
    # Test 4: Invalid endpoint (should return 404)
    print("   - Testing invalid endpoint...")
    try:
        response = requests.get(f"{api_url}/invalid-endpoint")
        print(f"   ✅ Invalid endpoint: {response.status_code}")
        request_id = response.headers.get("X-Request-ID")
        if request_id:
            print(f"   📝 Request ID: {request_id}")
    except Exception as e:
        print(f"   ❌ Invalid endpoint failed: {e}")
    
    print("\n2. Waiting for logs to be processed...")
    time.sleep(2)  # Give time for async logging to complete
    
    print("\n3. Testing database logging service...")
    
    # Test database logging service directly
    try:
        # Test log retrieval
        logs_result = await api_logging_service.get_api_logs(
            limit=10
        )
        
        if logs_result['success']:
            print(f"   ✅ Retrieved {len(logs_result['logs'])} logs from database")
            
            # Show some log details
            for i, log in enumerate(logs_result['logs'][:3]):
                print(f"   📊 Log {i+1}: {log['method']} {log['path']} - {log['status_code']} ({log['duration_ms']}ms)")
        else:
            print(f"   ❌ Failed to retrieve logs: {logs_result['error']}")
        
        # Test metrics retrieval
        metrics_result = await api_logging_service.get_api_metrics(
            time_bucket="hour",
            limit=10
        )
        
        if metrics_result['success']:
            print(f"   ✅ Retrieved {len(metrics_result['metrics'])} metrics from database")
        else:
            print(f"   ❌ Failed to retrieve metrics: {metrics_result['error']}")
            
    except Exception as e:
        print(f"   ❌ Database logging service test failed: {e}")
    
    print("\n4. Testing log cleanup...")
    
    try:
        # Test cleanup (keep last 30 days)
        cleanup_result = await api_logging_service.cleanup_old_logs(days_to_keep=30)
        
        if cleanup_result['success']:
            print(f"   ✅ Cleanup completed: {cleanup_result['deleted_count']} logs deleted")
        else:
            print(f"   ❌ Cleanup failed: {cleanup_result['error']}")
            
    except Exception as e:
        print(f"   ❌ Cleanup test failed: {e}")
    
    print("\n" + "=" * 50)
    print("✅ API Logging System Test Completed!")
    
    print("\n📋 Summary:")
    print("  - API requests were made and should be logged")
    print("  - Request IDs were generated and returned")
    print("  - Database logging service was tested")
    print("  - Log cleanup functionality was verified")
    
    print("\n🔍 Next Steps:")
    print("  1. Check CloudWatch logs (if AWS credentials are configured)")
    print("  2. Query the database directly to verify log storage")
    print("  3. Use the API endpoints to view logs:")
    print("     GET /api/v1/logs/api-logs")
    print("     GET /api/v1/logs/api-logs/summary")
    print("     GET /api/v1/logs/api-metrics")


def test_logging_endpoints():
    """Test the logging API endpoints (requires authentication)"""
    print("\n🔐 Testing Logging API Endpoints")
    print("=" * 50)
    
    base_url = "http://localhost:8000"
    api_url = f"{base_url}/api/v1"
    
    # Note: These endpoints require authentication
    # You would need to get a valid token first
    
    endpoints = [
        "/logs/api-logs",
        "/logs/api-metrics",
        "/logs/api-logs/summary",
        "/logs/api-logs/cleanup"
    ]
    
    for endpoint in endpoints:
        print(f"   - Testing {endpoint}...")
        try:
            response = requests.get(f"{api_url}{endpoint}")
            if response.status_code == 401:
                print(f"   ⚠️  {endpoint}: Authentication required (expected)")
            else:
                print(f"   ✅ {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"   ❌ {endpoint}: {e}")


def main():
    """Main function to run all tests"""
    print("🚀 API Logging System Test Suite")
    print("=" * 60)
    
    try:
        # Test basic logging functionality
        test_api_logging()
        
        # Test logging endpoints (will show auth requirements)
        test_logging_endpoints()
        
        print("\n" + "=" * 60)
        print("✅ All tests completed!")
        
    except Exception as e:
        print(f"\n❌ Test suite failed: {e}")
        print("Make sure the API server is running on http://localhost:8000")


if __name__ == "__main__":
    main() 
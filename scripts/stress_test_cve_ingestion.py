#!/usr/bin/env python3
"""
CVE Ingestion Stress Test Script
Simulates ingesting 10,000 CVEs to test system performance and scalability.
"""

import asyncio
import aiohttp
import json
import time
import random
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
import argparse
import statistics
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('stress_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    """Test result data class"""
    total_cves: int
    successful_ingestions: int
    failed_ingestions: int
    total_time: float
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    requests_per_second: float
    concurrent_requests: int
    errors: List[str]

class CVEStressTester:
    """CVE Ingestion Stress Tester"""
    
    def __init__(self, base_url: str, api_key: str = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = None
        self.results = []
        self.errors = []
        self.lock = threading.Lock()
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}' if self.api_key else ''
            },
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def generate_cve_data(self, cve_id: str) -> Dict[str, Any]:
        """Generate realistic CVE data"""
        severity_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        cwe_types = [
            'CWE-79', 'CWE-20', 'CWE-125', 'CWE-22', 'CWE-78',
            'CWE-287', 'CWE-434', 'CWE-352', 'CWE-200', 'CWE-120'
        ]
        
        # Generate random CVSS score
        cvss_base = round(random.uniform(0.1, 10.0), 1)
        
        return {
            "cve_id": cve_id,
            "description": f"Security vulnerability in {random.choice(['web application', 'database', 'network service', 'operating system'])} that could allow {random.choice(['remote code execution', 'privilege escalation', 'information disclosure', 'denial of service'])}",
            "severity": random.choice(severity_levels),
            "cvss_score": cvss_base,
            "cvss_vector": f"CVSS:3.1/AV:{random.choice(['N', 'A', 'L', 'P'])}/AC:{random.choice(['L', 'H'])}/PR:{random.choice(['N', 'L', 'H'])}/UI:{random.choice(['N', 'R'])}/S:{random.choice(['U', 'C'])}/C:{random.choice(['H', 'L', 'N'])}/I:{random.choice(['H', 'L', 'N'])}/A:{random.choice(['H', 'L', 'N'])}",
            "cwe_id": random.choice(cwe_types),
            "published_date": (datetime.now() - timedelta(days=random.randint(0, 365))).isoformat(),
            "last_modified_date": datetime.now().isoformat(),
            "references": [
                {
                    "url": f"https://example.com/security/{cve_id}",
                    "source": "Security Advisory"
                }
            ],
            "affected_products": [
                {
                    "vendor": random.choice(["Microsoft", "Oracle", "Adobe", "Google", "Mozilla"]),
                    "product": random.choice(["Windows", "Java", "Flash", "Chrome", "Firefox"]),
                    "version": f"{random.randint(1, 20)}.{random.randint(0, 99)}.{random.randint(0, 999)}"
                }
            ],
            "tags": random.sample([
                "rce", "xss", "sqli", "authentication", "authorization",
                "input-validation", "memory-corruption", "race-condition"
            ], random.randint(1, 3))
        }
    
    async def ingest_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a single CVE"""
        start_time = time.time()
        
        try:
            async with self.session.post(
                f"{self.base_url}/api/v1/cves",
                json=cve_data
            ) as response:
                response_time = time.time() - start_time
                
                if response.status == 201:
                    result = await response.json()
                    return {
                        "success": True,
                        "response_time": response_time,
                        "status_code": response.status,
                        "cve_id": cve_data["cve_id"],
                        "response": result
                    }
                else:
                    error_text = await response.text()
                    return {
                        "success": False,
                        "response_time": response_time,
                        "status_code": response.status,
                        "cve_id": cve_data["cve_id"],
                        "error": error_text
                    }
                    
        except Exception as e:
            response_time = time.time() - start_time
            return {
                "success": False,
                "response_time": response_time,
                "status_code": None,
                "cve_id": cve_data["cve_id"],
                "error": str(e)
            }
    
    async def run_batch(self, batch_size: int, concurrent_requests: int) -> List[Dict[str, Any]]:
        """Run a batch of CVE ingestions"""
        semaphore = asyncio.Semaphore(concurrent_requests)
        
        async def ingest_with_semaphore(cve_data):
            async with semaphore:
                return await self.ingest_cve(cve_data)
        
        # Generate batch of CVEs
        cve_batch = [
            self.generate_cve_data(f"CVE-{datetime.now().year}-{i:06d}")
            for i in range(batch_size)
        ]
        
        # Run concurrent ingestions
        tasks = [ingest_with_semaphore(cve_data) for cve_data in cve_batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                processed_results.append({
                    "success": False,
                    "response_time": 0,
                    "status_code": None,
                    "cve_id": "unknown",
                    "error": str(result)
                })
            else:
                processed_results.append(result)
        
        return processed_results
    
    async def run_stress_test(self, total_cves: int, batch_size: int = 100, concurrent_requests: int = 10) -> TestResult:
        """Run the complete stress test"""
        logger.info(f"Starting stress test: {total_cves} CVEs, batch size: {batch_size}, concurrent requests: {concurrent_requests}")
        
        start_time = time.time()
        all_results = []
        total_batches = (total_cves + batch_size - 1) // batch_size
        
        for batch_num in range(total_batches):
            batch_start = batch_num * batch_size
            current_batch_size = min(batch_size, total_cves - batch_start)
            
            logger.info(f"Processing batch {batch_num + 1}/{total_batches} ({current_batch_size} CVEs)")
            
            batch_results = await self.run_batch(current_batch_size, concurrent_requests)
            all_results.extend(batch_results)
            
            # Log progress
            successful = sum(1 for r in batch_results if r["success"])
            failed = len(batch_results) - successful
            logger.info(f"Batch {batch_num + 1} complete: {successful} successful, {failed} failed")
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        successful_results = [r for r in all_results if r["success"]]
        failed_results = [r for r in all_results if not r["success"]]
        
        response_times = [r["response_time"] for r in successful_results]
        
        return TestResult(
            total_cves=total_cves,
            successful_ingestions=len(successful_results),
            failed_ingestions=len(failed_results),
            total_time=total_time,
            avg_response_time=statistics.mean(response_times) if response_times else 0,
            min_response_time=min(response_times) if response_times else 0,
            max_response_time=max(response_times) if response_times else 0,
            requests_per_second=len(all_results) / total_time if total_time > 0 else 0,
            concurrent_requests=concurrent_requests,
            errors=[r["error"] for r in failed_results if r.get("error")]
        )

def print_results(result: TestResult):
    """Print test results in a formatted way"""
    print("\n" + "="*60)
    print("CVE INGESTION STRESS TEST RESULTS")
    print("="*60)
    print(f"Total CVEs Processed: {result.total_cves:,}")
    print(f"Successful Ingestions: {result.successful_ingestions:,}")
    print(f"Failed Ingestions: {result.failed_ingestions:,}")
    print(f"Success Rate: {(result.successful_ingestions/result.total_cves)*100:.2f}%")
    print(f"Total Time: {result.total_time:.2f} seconds")
    print(f"Requests per Second: {result.requests_per_second:.2f}")
    print(f"Concurrent Requests: {result.concurrent_requests}")
    print("\nResponse Time Statistics:")
    print(f"  Average: {result.avg_response_time:.3f} seconds")
    print(f"  Minimum: {result.min_response_time:.3f} seconds")
    print(f"  Maximum: {result.max_response_time:.3f} seconds")
    
    if result.errors:
        print(f"\nTop 5 Error Types:")
        error_counts = {}
        for error in result.errors:
            error_type = error.split(':')[0] if ':' in error else error[:50]
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
        
        for error_type, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {error_type}: {count} occurrences")
    
    print("="*60)

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='CVE Ingestion Stress Test')
    parser.add_argument('--url', default='http://localhost:8000', help='API base URL')
    parser.add_argument('--api-key', help='API key for authentication')
    parser.add_argument('--total-cves', type=int, default=10000, help='Total number of CVEs to ingest')
    parser.add_argument('--batch-size', type=int, default=100, help='Batch size for processing')
    parser.add_argument('--concurrent', type=int, default=10, help='Number of concurrent requests')
    parser.add_argument('--output', help='Output file for detailed results')
    
    args = parser.parse_args()
    
    logger.info(f"Starting CVE ingestion stress test")
    logger.info(f"Target: {args.total_cves:,} CVEs")
    logger.info(f"Batch size: {args.batch_size}")
    logger.info(f"Concurrent requests: {args.concurrent}")
    logger.info(f"API URL: {args.url}")
    
    async with CVEStressTester(args.url, args.api_key) as tester:
        result = await tester.run_stress_test(
            total_cves=args.total_cves,
            batch_size=args.batch_size,
            concurrent_requests=args.concurrent
        )
    
    print_results(result)
    
    # Save detailed results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                "test_configuration": {
                    "total_cves": args.total_cves,
                    "batch_size": args.batch_size,
                    "concurrent_requests": args.concurrent,
                    "api_url": args.url
                },
                "results": {
                    "total_cves": result.total_cves,
                    "successful_ingestions": result.successful_ingestions,
                    "failed_ingestions": result.failed_ingestions,
                    "total_time": result.total_time,
                    "avg_response_time": result.avg_response_time,
                    "min_response_time": result.min_response_time,
                    "max_response_time": result.max_response_time,
                    "requests_per_second": result.requests_per_second,
                    "concurrent_requests": result.concurrent_requests,
                    "errors": result.errors
                }
            }, f, indent=2)
        logger.info(f"Detailed results saved to {args.output}")

if __name__ == "__main__":
    asyncio.run(main()) 
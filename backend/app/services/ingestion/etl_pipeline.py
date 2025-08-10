"""
ETL Pipeline for Threat Intelligence Data Ingestion
Handles extraction, transformation, and loading of data from various sources.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

import boto3
import aiohttp
from botocore.exceptions import ClientError

from app.core.config import settings
from app.services.threat_intelligence import (
    NVDIntegration, VirusTotalIntegration, ShodanIntegration, MitreAttackIntegration
)

logger = logging.getLogger(__name__)


@dataclass
class IngestionMetadata:
    """Metadata for ingestion events"""
    source: str
    timestamp: datetime
    data_type: str
    record_count: int
    status: str
    error_message: Optional[str] = None
    processing_time: Optional[float] = None


class S3Loader:
    """Loads unstructured data to AWS S3"""
    
    def __init__(self):
        self.s3_client = boto3.client('s3')
        self.bucket_name = settings.S3_BUCKET
    
    async def load_unstructured(self, data: Dict[str, Any], file_key: str) -> bool:
        """Load unstructured data to S3"""
        try:
            await self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=file_key,
                Body=json.dumps(data, default=str),
                ContentType='application/json',
                Metadata={
                    'ingestion_timestamp': datetime.utcnow().isoformat(),
                    'data_type': data.get('type', 'unknown'),
                    'source': data.get('source', 'unknown')
                }
            )
            logger.info(f"Successfully loaded data to S3: {file_key}")
            return True
        except ClientError as e:
            logger.error(f"Failed to load data to S3: {e}")
            return False


class DynamoDBLoader:
    """Loads structured data and metadata to AWS DynamoDB"""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.threat_table = self.dynamodb.Table('threat_intelligence')
        self.metadata_table = self.dynamodb.Table('ingestion_metadata')
    
    async def load_structured(self, data: Dict[str, Any]) -> bool:
        """Load structured data to DynamoDB"""
        try:
            await self.threat_table.put_item(Item=data)
            return True
        except ClientError as e:
            logger.error(f"Failed to load structured data to DynamoDB: {e}")
            return False
    
    async def log_ingestion_event(self, metadata: IngestionMetadata) -> bool:
        """Log ingestion event metadata to DynamoDB"""
        try:
            event_data = {
                'source': metadata.source,
                'timestamp': metadata.timestamp.isoformat(),
                'data_type': metadata.data_type,
                'record_count': metadata.record_count,
                'status': metadata.status,
                'error_message': metadata.error_message,
                'processing_time': metadata.processing_time
            }
            
            await self.metadata_table.put_item(Item=event_data)
            logger.info(f"Logged ingestion event: {metadata.source} - {metadata.status}")
            return True
        except ClientError as e:
            logger.error(f"Failed to log ingestion event: {e}")
            return False


class NVDExtractor:
    """Extracts CVE data from NVD API"""
    
    def __init__(self):
        self.nvd = NVDIntegration()
    
    async def extract_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:
        """Extract recent CVEs from NVD"""
        try:
            start_time = datetime.utcnow()
            cves = await self.nvd.get_recent_cves(days)
            
            # Transform to standard format
            transformed_data = []
            for cve in cves:
                if 'cve' in cve:
                    transformed_data.append({
                        'id': cve['cve']['id'],
                        'type': 'cve',
                        'source': 'nvd',
                        'description': cve['cve'].get('descriptions', [{}])[0].get('value', ''),
                        'cvss_score': self._extract_cvss_score(cve),
                        'severity': self._extract_severity(cve),
                        'published_date': cve['cve'].get('published', ''),
                        'last_modified': cve['cve'].get('lastModified', ''),
                        'raw_data': cve,
                        'ingestion_timestamp': datetime.utcnow().isoformat()
                    })
            
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                'data': transformed_data,
                'metadata': IngestionMetadata(
                    source='nvd',
                    timestamp=datetime.utcnow(),
                    data_type='cve',
                    record_count=len(transformed_data),
                    status='success',
                    processing_time=processing_time
                )
            }
        except Exception as e:
            logger.error(f"Failed to extract NVD data: {e}")
            return {
                'data': [],
                'metadata': IngestionMetadata(
                    source='nvd',
                    timestamp=datetime.utcnow(),
                    data_type='cve',
                    record_count=0,
                    status='error',
                    error_message=str(e)
                )
            }
    
    def _extract_cvss_score(self, cve_data: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from CVE data"""
        try:
            metrics = cve_data['cve'].get('metrics', {})
            if 'cvssMetricV31' in metrics:
                return metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            elif 'cvssMetricV30' in metrics:
                return metrics['cvssMetricV30'][0]['cvssData']['baseScore']
            elif 'cvssMetricV2' in metrics:
                return metrics['cvssMetricV2'][0]['cvssData']['baseScore']
        except (KeyError, IndexError):
            pass
        return None
    
    def _extract_severity(self, cve_data: Dict[str, Any]) -> str:
        """Extract severity from CVE data"""
        try:
            metrics = cve_data['cve'].get('metrics', {})
            if 'cvssMetricV31' in metrics:
                return metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
            elif 'cvssMetricV30' in metrics:
                return metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
        except (KeyError, IndexError):
            pass
        return 'UNKNOWN'


class VirusTotalExtractor:
    """Extracts malware data from VirusTotal API"""
    
    def __init__(self):
        self.virustotal = VirusTotalIntegration(settings.VIRUSTOTAL_API_KEY)
    
    async def extract_malware_reports(self, file_hashes: List[str]) -> Dict[str, Any]:
        """Extract malware reports for given file hashes"""
        try:
            start_time = datetime.utcnow()
            results = []
            
            for file_hash in file_hashes:
                report = await self.virustotal.analyze_file(file_hash)
                if report and report.get('response_code') == 1:
                    results.append({
                        'id': file_hash,
                        'type': 'malware_report',
                        'source': 'virustotal',
                        'positives': report.get('positives', 0),
                        'total': report.get('total', 0),
                        'scan_date': report.get('scan_date', ''),
                        'scans': report.get('scans', {}),
                        'raw_data': report,
                        'ingestion_timestamp': datetime.utcnow().isoformat()
                    })
            
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                'data': results,
                'metadata': IngestionMetadata(
                    source='virustotal',
                    timestamp=datetime.utcnow(),
                    data_type='malware_report',
                    record_count=len(results),
                    status='success',
                    processing_time=processing_time
                )
            }
        except Exception as e:
            logger.error(f"Failed to extract VirusTotal data: {e}")
            return {
                'data': [],
                'metadata': IngestionMetadata(
                    source='virustotal',
                    timestamp=datetime.utcnow(),
                    data_type='malware_report',
                    record_count=0,
                    status='error',
                    error_message=str(e)
                )
            }


class ShodanExtractor:
    """Extracts IP/device exposure data from Shodan API"""
    
    def __init__(self):
        self.shodan = ShodanIntegration(settings.SHODAN_API_KEY)
    
    async def extract_exposure_data(self, ips: List[str]) -> Dict[str, Any]:
        """Extract exposure data for given IP addresses"""
        try:
            start_time = datetime.utcnow()
            results = []
            
            for ip in ips:
                host_info = await self.shodan.get_host_info(ip)
                if host_info:
                    results.append({
                        'id': ip,
                        'type': 'exposure_data',
                        'source': 'shodan',
                        'hostnames': host_info.get('hostnames', []),
                        'ports': host_info.get('ports', []),
                        'vulns': host_info.get('vulns', []),
                        'org': host_info.get('org', ''),
                        'location': host_info.get('location', {}),
                        'data': host_info.get('data', []),
                        'raw_data': host_info,
                        'ingestion_timestamp': datetime.utcnow().isoformat()
                    })
            
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                'data': results,
                'metadata': IngestionMetadata(
                    source='shodan',
                    timestamp=datetime.utcnow(),
                    data_type='exposure_data',
                    record_count=len(results),
                    status='success',
                    processing_time=processing_time
                )
            }
        except Exception as e:
            logger.error(f"Failed to extract Shodan data: {e}")
            return {
                'data': [],
                'metadata': IngestionMetadata(
                    source='shodan',
                    timestamp=datetime.utcnow(),
                    data_type='exposure_data',
                    record_count=0,
                    status='error',
                    error_message=str(e)
                )
            }


class ETLPipeline:
    """Main ETL pipeline orchestrator"""
    
    def __init__(self):
        self.extractors = {
            'nvd': NVDExtractor(),
            'virustotal': VirusTotalExtractor(),
            'shodan': ShodanExtractor()
        }
        self.s3_loader = S3Loader()
        self.dynamodb_loader = DynamoDBLoader()
    
    async def process_nvd_ingestion(self, days: int = 7) -> bool:
        """Process NVD CVE ingestion"""
        try:
            # Extract
            extraction_result = await self.extractors['nvd'].extract_recent_cves(days)
            data = extraction_result['data']
            metadata = extraction_result['metadata']
            
            # Load to S3
            file_key = f"raw_data/nvd/cves_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            s3_success = await self.s3_loader.load_unstructured(data, file_key)
            
            # Load structured data to DynamoDB
            db_success = True
            for item in data:
                if not await self.dynamodb_loader.load_structured(item):
                    db_success = False
            
            # Log ingestion event
            await self.dynamodb_loader.log_ingestion_event(metadata)
            
            return s3_success and db_success
        except Exception as e:
            logger.error(f"Failed to process NVD ingestion: {e}")
            return False
    
    async def process_virustotal_ingestion(self, file_hashes: List[str]) -> bool:
        """Process VirusTotal malware report ingestion"""
        try:
            # Extract
            extraction_result = await self.extractors['virustotal'].extract_malware_reports(file_hashes)
            data = extraction_result['data']
            metadata = extraction_result['metadata']
            
            # Load to S3
            file_key = f"raw_data/virustotal/malware_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            s3_success = await self.s3_loader.load_unstructured(data, file_key)
            
            # Load structured data to DynamoDB
            db_success = True
            for item in data:
                if not await self.dynamodb_loader.load_structured(item):
                    db_success = False
            
            # Log ingestion event
            await self.dynamodb_loader.log_ingestion_event(metadata)
            
            return s3_success and db_success
        except Exception as e:
            logger.error(f"Failed to process VirusTotal ingestion: {e}")
            return False
    
    async def process_shodan_ingestion(self, ips: List[str]) -> bool:
        """Process Shodan exposure data ingestion"""
        try:
            # Extract
            extraction_result = await self.extractors['shodan'].extract_exposure_data(ips)
            data = extraction_result['data']
            metadata = extraction_result['metadata']
            
            # Load to S3
            file_key = f"raw_data/shodan/exposure_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            s3_success = await self.s3_loader.load_unstructured(data, file_key)
            
            # Load structured data to DynamoDB
            db_success = True
            for item in data:
                if not await self.dynamodb_loader.load_structured(item):
                    db_success = False
            
            # Log ingestion event
            await self.dynamodb_loader.log_ingestion_event(metadata)
            
            return s3_success and db_success
        except Exception as e:
            logger.error(f"Failed to process Shodan ingestion: {e}")
            return False
    
    async def run_full_ingestion(self) -> Dict[str, bool]:
        """Run full ingestion pipeline for all sources"""
        results = {}
        
        # NVD ingestion (daily)
        results['nvd'] = await self.process_nvd_ingestion(days=1)
        
        # VirusTotal ingestion (requires file hashes - would come from other sources)
        # For demo purposes, using empty list
        results['virustotal'] = await self.process_virustotal_ingestion([])
        
        # Shodan ingestion (requires IPs - would come from asset inventory)
        # For demo purposes, using empty list
        results['shodan'] = await self.process_shodan_ingestion([])
        
        return results 
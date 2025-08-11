"""
Enhanced ETL Pipeline with S3 Storage Integration
Provides comprehensive data ingestion with S3 storage for raw data.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from app.services.storage.s3_storage import S3StorageService, S3StorageConfig
from app.services.ingestion.extractors import (
    NVDExtractor, VirusTotalExtractor, ShodanExtractor
)
from app.services.database.dynamodb_service import DynamoDBService
from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class IngestionResult:
    """Result of data ingestion operation"""
    success: bool
    source: str
    data_type: str
    record_count: int
    s3_file_key: Optional[str] = None
    error_message: Optional[str] = None
    processing_time: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None


class EnhancedETLPipeline:
    """Enhanced ETL pipeline with S3 storage integration"""
    
    def __init__(self):
        # Initialize storage services
        self.s3_storage = S3StorageService()
        self.dynamodb_service = DynamoDBService()
        
        # Initialize extractors
        self.extractors = {
            'nvd': NVDExtractor(),
            'virustotal': VirusTotalExtractor(),
            'shodan': ShodanExtractor()
        }
        
        # Data type mappings
        self.data_type_mappings = {
            'nvd': 'vulnerability',
            'virustotal': 'malware',
            'shodan': 'exposure'
        }
    
    async def ingest_nvd_data(self, days: int = 7) -> IngestionResult:
        """Ingest NVD CVE data with S3 storage"""
        start_time = datetime.utcnow()
        
        try:
            logger.info(f"Starting NVD data ingestion for {days} days")
            
            # Extract data
            extractor = self.extractors['nvd']
            extraction_result = await extractor.extract_recent_cves(days)
            
            if not extraction_result['success']:
                return IngestionResult(
                    success=False,
                    source='nvd',
                    data_type='vulnerability',
                    record_count=0,
                    error_message=extraction_result.get('error', 'Extraction failed')
                )
            
            data = extraction_result['data']
            metadata = extraction_result['metadata']
            
            # Store raw data in S3
            s3_file_key = await self.s3_storage.store_raw_data(
                data=data,
                data_type='vulnerability',
                source='nvd',
                metadata={
                    'days_requested': days,
                    'extraction_timestamp': metadata.get('timestamp'),
                    'api_version': metadata.get('api_version', '2.0')
                }
            )
            
            # Store structured data in DynamoDB
            db_success = await self._store_structured_data(data, 'vulnerability', 'nvd')
            
            # Calculate processing time
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            logger.info(f"NVD ingestion completed: {len(data)} records in {processing_time:.2f}s")
            
            # Log ingestion event
            await self.dynamodb_service.log_ingestion_event(
                source="nvd",
                data_type="vulnerability",
                timestamp=datetime.utcnow(),
                record_count=len(data),
                status="success",
                processing_time=processing_time,
                extra={"s3_file_key": s3_file_key}
            )
            
            return IngestionResult(
                success=db_success,
                source='nvd',
                data_type='vulnerability',
                record_count=len(data),
                s3_file_key=s3_file_key,
                processing_time=processing_time,
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"NVD ingestion failed: {e}")
            # Log failed event
            await self.dynamodb_service.log_ingestion_event(
                source="nvd",
                data_type="vulnerability",
                timestamp=datetime.utcnow(),
                record_count=0,
                status="error",
                error_message=str(e)
            )
            return IngestionResult(
                success=False,
                source='nvd',
                data_type='vulnerability',
                record_count=0,
                error_message=str(e)
            )
    
    async def ingest_virustotal_data(self, file_hashes: List[str]) -> IngestionResult:
        """Ingest VirusTotal malware data with S3 storage"""
        start_time = datetime.utcnow()
        
        try:
            logger.info(f"Starting VirusTotal data ingestion for {len(file_hashes)} hashes")
            
            # Extract data
            extractor = self.extractors['virustotal']
            extraction_result = await extractor.extract_malware_reports(file_hashes)
            
            if not extraction_result['success']:
                return IngestionResult(
                    success=False,
                    source='virustotal',
                    data_type='malware',
                    record_count=0,
                    error_message=extraction_result.get('error', 'Extraction failed')
                )
            
            data = extraction_result['data']
            metadata = extraction_result['metadata']
            
            # Store raw data in S3
            s3_file_key = await self.s3_storage.store_raw_data(
                data=data,
                data_type='malware',
                source='virustotal',
                metadata={
                    'hash_count': len(file_hashes),
                    'extraction_timestamp': metadata.get('timestamp'),
                    'api_version': metadata.get('api_version', '3.0')
                }
            )
            
            # Store structured data in DynamoDB
            db_success = await self._store_structured_data(data, 'malware', 'virustotal')
            
            # Calculate processing time
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            logger.info(f"VirusTotal ingestion completed: {len(data)} records in {processing_time:.2f}s")
            
            # Log ingestion event
            await self.dynamodb_service.log_ingestion_event(
                source="virustotal",
                data_type="malware",
                timestamp=datetime.utcnow(),
                record_count=len(data),
                status="success",
                processing_time=processing_time,
                extra={"s3_file_key": s3_file_key, "hash_count": len(file_hashes)}
            )
            
            return IngestionResult(
                success=db_success,
                source='virustotal',
                data_type='malware',
                record_count=len(data),
                s3_file_key=s3_file_key,
                processing_time=processing_time,
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"VirusTotal ingestion failed: {e}")
            # Log failed event
            await self.dynamodb_service.log_ingestion_event(
                source="virustotal",
                data_type="malware",
                timestamp=datetime.utcnow(),
                record_count=0,
                status="error",
                error_message=str(e)
            )
            return IngestionResult(
                success=False,
                source='virustotal',
                data_type='malware',
                record_count=0,
                error_message=str(e)
            )
    
    async def ingest_shodan_data(self, ips: List[str]) -> IngestionResult:
        """Ingest Shodan exposure data with S3 storage"""
        start_time = datetime.utcnow()
        
        try:
            logger.info(f"Starting Shodan data ingestion for {len(ips)} IPs")
            
            # Extract data
            extractor = self.extractors['shodan']
            extraction_result = await extractor.extract_exposure_data(ips)
            
            if not extraction_result['success']:
                return IngestionResult(
                    success=False,
                    source='shodan',
                    data_type='exposure',
                    record_count=0,
                    error_message=extraction_result.get('error', 'Extraction failed')
                )
            
            data = extraction_result['data']
            metadata = extraction_result['metadata']
            
            # Store raw data in S3
            s3_file_key = await self.s3_storage.store_raw_data(
                data=data,
                data_type='exposure',
                source='shodan',
                metadata={
                    'ip_count': len(ips),
                    'extraction_timestamp': metadata.get('timestamp'),
                    'api_version': metadata.get('api_version', '1.0')
                }
            )
            
            # Store structured data in DynamoDB
            db_success = await self._store_structured_data(data, 'exposure', 'shodan')
            
            # Calculate processing time
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            logger.info(f"Shodan ingestion completed: {len(data)} records in {processing_time:.2f}s")
            
            # Log ingestion event
            await self.dynamodb_service.log_ingestion_event(
                source="shodan",
                data_type="exposure",
                timestamp=datetime.utcnow(),
                record_count=len(data),
                status="success",
                processing_time=processing_time,
                extra={"s3_file_key": s3_file_key, "ip_count": len(ips)}
            )
            
            return IngestionResult(
                success=db_success,
                source='shodan',
                data_type='exposure',
                record_count=len(data),
                s3_file_key=s3_file_key,
                processing_time=processing_time,
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"Shodan ingestion failed: {e}")
            # Log failed event
            await self.dynamodb_service.log_ingestion_event(
                source="shodan",
                data_type="exposure",
                timestamp=datetime.utcnow(),
                record_count=0,
                status="error",
                error_message=str(e)
            )
            return IngestionResult(
                success=False,
                source='shodan',
                data_type='exposure',
                record_count=0,
                error_message=str(e)
            )
    
    async def run_full_ingestion(self) -> Dict[str, IngestionResult]:
        """Run full ingestion pipeline for all sources"""
        logger.info("Starting full ingestion pipeline")
        
        results = {}
        
        # NVD ingestion (daily)
        results['nvd'] = await self.ingest_nvd_data(days=1)
        
        # VirusTotal ingestion (requires file hashes)
        # For demo purposes, using empty list
        results['virustotal'] = await self.ingest_virustotal_data([])
        
        # Shodan ingestion (requires IPs)
        # For demo purposes, using empty list
        results['shodan'] = await self.ingest_shodan_data([])
        
        # Log summary
        successful_sources = [source for source, result in results.items() if result.success]
        failed_sources = [source for source, result in results.items() if not result.success]
        
        logger.info(f"Full ingestion completed. Successful: {successful_sources}, Failed: {failed_sources}")
        
        return results
    
    async def _store_structured_data(self, data: List[Dict[str, Any]], data_type: str, source: str) -> bool:
        """Store structured data in DynamoDB"""
        try:
            success_count = 0
            for item in data:
                # Add metadata
                structured_item = {
                    **item,
                    'data_type': data_type,
                    'source': source,
                    'ingestion_timestamp': datetime.utcnow().isoformat(),
                    's3_stored': True
                }
                
                if await self.dynamodb_service.store_threat_data(structured_item):
                    success_count += 1
            
            logger.info(f"Stored {success_count}/{len(data)} structured records in DynamoDB")
            return success_count == len(data)
            
        except Exception as e:
            logger.error(f"Failed to store structured data: {e}")
            return False
    
    async def get_ingestion_metrics(self, days: int = 30) -> Dict[str, Any]:
        """Get ingestion metrics for the specified period"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Get S3 storage metrics
            s3_metrics = await self.s3_storage.get_storage_metrics()
            
            # Get DynamoDB metrics
            db_metrics = await self.dynamodb_service.get_ingestion_metrics(start_date, end_date)
            
            return {
                'period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'days': days
                },
                's3_storage': s3_metrics,
                'database': db_metrics,
                'summary': {
                    'total_files_stored': s3_metrics.get('total_files', 0),
                    'total_data_size': s3_metrics.get('total_size', 0),
                    'total_records_ingested': db_metrics.get('total_records', 0)
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get ingestion metrics: {e}")
            raise
    
    async def cleanup_old_data(self, days_old: int = 90) -> Dict[str, int]:
        """Clean up old data from both S3 and DynamoDB"""
        try:
            logger.info(f"Starting cleanup of data older than {days_old} days")
            
            # Clean up S3
            s3_cleaned = await self.s3_storage.cleanup_old_data(days_old)
            
            # Clean up DynamoDB
            db_cleaned = await self.dynamodb_service.cleanup_old_records(days_old)
            
            logger.info(f"Cleanup completed: S3={s3_cleaned} files, DynamoDB={db_cleaned} records")
            
            return {
                's3_files_cleaned': s3_cleaned,
                'db_records_cleaned': db_cleaned
            }
            
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")
            raise
    
    async def backup_critical_data(self) -> Dict[str, str]:
        """Create backups of critical data"""
        try:
            logger.info("Starting critical data backup")
            
            # Get recent data files
            recent_files = await self.s3_storage.list_data_files(
                date_range=(datetime.utcnow() - timedelta(days=7), datetime.utcnow())
            )
            
            backup_keys = {}
            for file_info in recent_files[:10]:  # Backup last 10 files
                backup_key = await self.s3_storage.backup_data(file_info['key'])
                backup_keys[file_info['key']] = backup_key
            
            logger.info(f"Backup completed: {len(backup_keys)} files backed up")
            return backup_keys
            
        except Exception as e:
            logger.error(f"Failed to backup critical data: {e}")
            raise 
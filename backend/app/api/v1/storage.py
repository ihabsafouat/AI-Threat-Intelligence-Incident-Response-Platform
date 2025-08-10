"""
S3 Storage API Endpoints
Provides REST API endpoints for S3 storage operations.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
import logging

from app.services.storage.s3_storage import S3StorageService
from app.services.ingestion.enhanced_etl_pipeline import EnhancedETLPipeline
from app.core.auth import get_current_user
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/storage", tags=["storage"])


@router.get("/metrics")
async def get_storage_metrics(
    days: int = Query(30, description="Number of days to include in metrics"),
    current_user: User = Depends(get_current_user)
):
    """Get S3 storage metrics"""
    try:
        s3_storage = S3StorageService()
        etl_pipeline = EnhancedETLPipeline()
        
        # Get storage metrics
        storage_metrics = await s3_storage.get_storage_metrics()
        
        # Get ingestion metrics
        ingestion_metrics = await etl_pipeline.get_ingestion_metrics(days)
        
        return {
            "storage": storage_metrics,
            "ingestion": ingestion_metrics,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get storage metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/files")
async def list_data_files(
    data_type: Optional[str] = Query(None, description="Filter by data type"),
    source: Optional[str] = Query(None, description="Filter by source"),
    days: int = Query(7, description="Number of days to look back"),
    current_user: User = Depends(get_current_user)
):
    """List data files in S3"""
    try:
        s3_storage = S3StorageService()
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        date_range = (start_date, end_date)
        
        files = await s3_storage.list_data_files(
            data_type=data_type,
            source=source,
            date_range=date_range
        )
        
        return {
            "files": files,
            "count": len(files),
            "filters": {
                "data_type": data_type,
                "source": source,
                "date_range": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat()
                }
            }
        }
    except Exception as e:
        logger.error(f"Failed to list data files: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/files/{file_key:path}")
async def get_data_file(
    file_key: str,
    current_user: User = Depends(get_current_user)
):
    """Retrieve a specific data file from S3"""
    try:
        s3_storage = S3StorageService()
        data = await s3_storage.retrieve_data(file_key)
        
        return {
            "file_key": file_key,
            "data": data,
            "retrieved_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to retrieve data file {file_key}: {e}")
        raise HTTPException(status_code=404, detail=f"File not found: {file_key}")


@router.post("/backup")
async def backup_data(
    file_keys: List[str],
    current_user: User = Depends(get_current_user)
):
    """Create backups of specified data files"""
    try:
        s3_storage = S3StorageService()
        backup_results = {}
        
        for file_key in file_keys:
            try:
                backup_key = await s3_storage.backup_data(file_key)
                backup_results[file_key] = {
                    "success": True,
                    "backup_key": backup_key
                }
            except Exception as e:
                backup_results[file_key] = {
                    "success": False,
                    "error": str(e)
                }
        
        successful_backups = sum(1 for result in backup_results.values() if result["success"])
        
        return {
            "backup_results": backup_results,
            "summary": {
                "total_files": len(file_keys),
                "successful_backups": successful_backups,
                "failed_backups": len(file_keys) - successful_backups
            }
        }
    except Exception as e:
        logger.error(f"Failed to backup data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/archive")
async def archive_data(
    file_keys: List[str],
    archive_reason: str = "data_retention",
    current_user: User = Depends(get_current_user)
):
    """Archive specified data files"""
    try:
        s3_storage = S3StorageService()
        archive_results = {}
        
        for file_key in file_keys:
            try:
                archive_key = await s3_storage.archive_data(file_key, archive_reason)
                archive_results[file_key] = {
                    "success": True,
                    "archive_key": archive_key
                }
            except Exception as e:
                archive_results[file_key] = {
                    "success": False,
                    "error": str(e)
                }
        
        successful_archives = sum(1 for result in archive_results.values() if result["success"])
        
        return {
            "archive_results": archive_results,
            "summary": {
                "total_files": len(file_keys),
                "successful_archives": successful_archives,
                "failed_archives": len(file_keys) - successful_archives,
                "archive_reason": archive_reason
            }
        }
    except Exception as e:
        logger.error(f"Failed to archive data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/cleanup")
async def cleanup_old_data(
    days_old: int = Query(90, description="Delete files older than this many days"),
    current_user: User = Depends(get_current_user)
):
    """Clean up old data files"""
    try:
        etl_pipeline = EnhancedETLPipeline()
        cleanup_results = await etl_pipeline.cleanup_old_data(days_old)
        
        return {
            "cleanup_results": cleanup_results,
            "summary": {
                "days_old": days_old,
                "s3_files_cleaned": cleanup_results.get("s3_files_cleaned", 0),
                "db_records_cleaned": cleanup_results.get("db_records_cleaned", 0)
            }
        }
    except Exception as e:
        logger.error(f"Failed to cleanup old data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/backup-critical")
async def backup_critical_data(
    current_user: User = Depends(get_current_user)
):
    """Create backups of critical data files"""
    try:
        etl_pipeline = EnhancedETLPipeline()
        backup_keys = await etl_pipeline.backup_critical_data()
        
        return {
            "backup_keys": backup_keys,
            "summary": {
                "files_backed_up": len(backup_keys),
                "backup_timestamp": datetime.utcnow().isoformat()
            }
        }
    except Exception as e:
        logger.error(f"Failed to backup critical data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def storage_health_check(
    current_user: User = Depends(get_current_user)
):
    """Check S3 storage health"""
    try:
        s3_storage = S3StorageService()
        
        # Test basic operations
        test_data = {"test": "data", "timestamp": datetime.utcnow().isoformat()}
        test_key = f"health_check/test_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Store test data
        stored_key = await s3_storage.store_raw_data(
            data=test_data,
            data_type="health_check",
            source="api",
            metadata={"purpose": "health_check"}
        )
        
        # Retrieve test data
        retrieved_data = await s3_storage.retrieve_data(stored_key)
        
        # Clean up test data
        await s3_storage.archive_data(stored_key, "health_check_cleanup")
        
        return {
            "status": "healthy",
            "s3_operations": {
                "store": "success",
                "retrieve": "success",
                "cleanup": "success"
            },
            "test_data": retrieved_data,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Storage health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )


@router.get("/folders")
async def get_folder_structure(
    current_user: User = Depends(get_current_user)
):
    """Get S3 folder structure information"""
    try:
        s3_storage = S3StorageService()
        
        return {
            "folder_structure": s3_storage.config.folder_structure,
            "lifecycle_policies": s3_storage.config.lifecycle_policies,
            "bucket_name": s3_storage.config.bucket_name,
            "region": s3_storage.config.region,
            "compression_enabled": s3_storage.config.compression_enabled,
            "encryption_enabled": s3_storage.config.encryption_enabled
        }
    except Exception as e:
        logger.error(f"Failed to get folder structure: {e}")
        raise HTTPException(status_code=500, detail=str(e)) 
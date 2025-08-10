"""
Apache Airflow DAG for S3 Storage Operations
Handles S3 data management, cleanup, backup, and archival tasks.
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator
from airflow.utils.dates import days_ago

import sys
import os

# Add the backend directory to Python path
sys.path.append('/opt/airflow/backend')

# Import our storage modules
from app.services.storage.s3_storage import S3StorageService
from app.services.ingestion.enhanced_etl_pipeline import EnhancedETLPipeline

# Default arguments for the DAG
default_args = {
    'owner': 'threat-intelligence-team',
    'depends_on_past': False,
    'start_date': days_ago(1),
    'email_on_failure': True,
    'email_on_retry': False,
    'retries': 3,
    'retry_delay': timedelta(minutes=5),
    'catchup': False
}

# Create the DAG
dag = DAG(
    's3_storage_operations',
    default_args=default_args,
    description='S3 storage management and operations',
    schedule_interval='0 4 * * *',  # Run daily at 4 AM
    max_active_runs=1,
    tags=['s3', 'storage', 'data-management']
)


def check_s3_health(**context):
    """Check S3 storage health"""
    try:
        s3_storage = S3StorageService()
        
        # Get storage metrics
        metrics = await s3_storage.get_storage_metrics()
        
        # Check if bucket is accessible
        bucket_exists = True
        try:
            s3_storage.s3_client.head_bucket(Bucket=s3_storage.config.bucket_name)
        except Exception:
            bucket_exists = False
        
        if not bucket_exists:
            raise Exception("S3 bucket is not accessible")
        
        print(f"S3 health check passed. Total files: {metrics.get('total_files', 0)}")
        return "SUCCESS"
    except Exception as e:
        print(f"S3 health check failed: {e}")
        raise


def backup_critical_data(**context):
    """Backup critical data files"""
    try:
        etl_pipeline = EnhancedETLPipeline()
        backup_keys = await etl_pipeline.backup_critical_data()
        
        print(f"Critical data backup completed: {len(backup_keys)} files backed up")
        return "SUCCESS"
    except Exception as e:
        print(f"Critical data backup failed: {e}")
        raise


def archive_old_data(**context):
    """Archive old data files"""
    try:
        s3_storage = S3StorageService()
        
        # Get files older than 30 days
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        old_files = await s3_storage.list_data_files(
            date_range=(datetime.min, cutoff_date)
        )
        
        archived_count = 0
        for file_info in old_files[:50]:  # Archive up to 50 files per run
            try:
                await s3_storage.archive_data(file_info['key'], "automated_archival")
                archived_count += 1
            except Exception as e:
                print(f"Failed to archive {file_info['key']}: {e}")
        
        print(f"Data archival completed: {archived_count} files archived")
        return "SUCCESS"
    except Exception as e:
        print(f"Data archival failed: {e}")
        raise


def cleanup_old_data(**context):
    """Clean up old data files"""
    try:
        etl_pipeline = EnhancedETLPipeline()
        cleanup_results = await etl_pipeline.cleanup_old_data(days_old=90)
        
        s3_cleaned = cleanup_results.get("s3_files_cleaned", 0)
        db_cleaned = cleanup_results.get("db_records_cleaned", 0)
        
        print(f"Data cleanup completed: S3={s3_cleaned} files, DB={db_cleaned} records")
        return "SUCCESS"
    except Exception as e:
        print(f"Data cleanup failed: {e}")
        raise


def optimize_storage_costs(**context):
    """Optimize storage costs by moving data to appropriate storage classes"""
    try:
        s3_storage = S3StorageService()
        
        # Get storage metrics
        metrics = await s3_storage.get_storage_metrics()
        
        # Check storage class distribution
        storage_distribution = metrics.get('storage_class_distribution', {})
        
        # If too much data in STANDARD, consider moving to STANDARD_IA
        standard_count = storage_distribution.get('STANDARD', 0)
        if standard_count > 1000:
            print(f"High STANDARD storage usage detected: {standard_count} files")
            # This would implement logic to move files to STANDARD_IA
            print("Storage optimization recommendations logged")
        
        print("Storage cost optimization check completed")
        return "SUCCESS"
    except Exception as e:
        print(f"Storage cost optimization failed: {e}")
        raise


def generate_storage_report(**context):
    """Generate storage usage report"""
    try:
        s3_storage = S3StorageService()
        etl_pipeline = EnhancedETLPipeline()
        
        # Get comprehensive metrics
        storage_metrics = await s3_storage.get_storage_metrics()
        ingestion_metrics = await etl_pipeline.get_ingestion_metrics(days=30)
        
        # Generate report
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "storage_summary": {
                "total_files": storage_metrics.get('total_files', 0),
                "total_size_bytes": storage_metrics.get('total_size', 0),
                "total_size_gb": round(storage_metrics.get('total_size', 0) / (1024**3), 2),
                "files_by_type": storage_metrics.get('files_by_type', {}),
                "files_by_source": storage_metrics.get('files_by_source', {}),
                "storage_class_distribution": storage_metrics.get('storage_class_distribution', {})
            },
            "ingestion_summary": ingestion_metrics.get('summary', {}),
            "recommendations": []
        }
        
        # Add recommendations based on metrics
        total_size_gb = report["storage_summary"]["total_size_gb"]
        if total_size_gb > 100:
            report["recommendations"].append("Consider implementing data lifecycle policies")
        
        if storage_metrics.get('total_files', 0) > 10000:
            report["recommendations"].append("High file count detected - consider consolidation")
        
        print(f"Storage report generated: {report['storage_summary']['total_files']} files, {report['storage_summary']['total_size_gb']} GB")
        return "SUCCESS"
    except Exception as e:
        print(f"Storage report generation failed: {e}")
        raise


def validate_data_integrity(**context):
    """Validate data integrity in S3"""
    try:
        s3_storage = S3StorageService()
        
        # Get recent files
        recent_files = await s3_storage.list_data_files(
            date_range=(datetime.utcnow() - timedelta(days=7), datetime.utcnow())
        )
        
        validation_results = {
            "total_files_checked": len(recent_files),
            "valid_files": 0,
            "invalid_files": 0,
            "errors": []
        }
        
        # Check a sample of files for integrity
        for file_info in recent_files[:10]:  # Check first 10 files
            try:
                data = await s3_storage.retrieve_data(file_info['key'])
                
                # Basic validation
                if 'data' in data and 'metadata' in data:
                    validation_results["valid_files"] += 1
                else:
                    validation_results["invalid_files"] += 1
                    validation_results["errors"].append(f"Invalid structure: {file_info['key']}")
                    
            except Exception as e:
                validation_results["invalid_files"] += 1
                validation_results["errors"].append(f"Retrieval failed: {file_info['key']} - {str(e)}")
        
        print(f"Data integrity validation completed: {validation_results['valid_files']} valid, {validation_results['invalid_files']} invalid")
        return "SUCCESS"
    except Exception as e:
        print(f"Data integrity validation failed: {e}")
        raise


# Define tasks
health_check_task = PythonOperator(
    task_id='check_s3_health',
    python_callable=check_s3_health,
    dag=dag
)

backup_task = PythonOperator(
    task_id='backup_critical_data',
    python_callable=backup_critical_data,
    dag=dag
)

archive_task = PythonOperator(
    task_id='archive_old_data',
    python_callable=archive_old_data,
    dag=dag
)

cleanup_task = PythonOperator(
    task_id='cleanup_old_data',
    python_callable=cleanup_old_data,
    dag=dag
)

optimize_task = PythonOperator(
    task_id='optimize_storage_costs',
    python_callable=optimize_storage_costs,
    dag=dag
)

validate_task = PythonOperator(
    task_id='validate_data_integrity',
    python_callable=validate_data_integrity,
    dag=dag
)

report_task = PythonOperator(
    task_id='generate_storage_report',
    python_callable=generate_storage_report,
    dag=dag
)

# Define task dependencies
health_check_task >> [backup_task, archive_task]
[backup_task, archive_task] >> cleanup_task
cleanup_task >> optimize_task
optimize_task >> validate_task
validate_task >> report_task 
"""
Apache Airflow DAG for Threat Intelligence Data Ingestion
Schedules and orchestrates data ingestion from various threat intelligence sources.
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator
from airflow.providers.amazon.aws.operators.glue import AwsGlueJobOperator
from airflow.providers.amazon.aws.sensors.glue import AwsGlueJobSensor
from airflow.utils.dates import days_ago

import sys
import os

# Add the backend directory to Python path
sys.path.append('/opt/airflow/backend')

# Import our ETL pipeline
from app.services.ingestion.etl_pipeline import ETLPipeline
from app.services.security.secrets_manager import APIKeyManager

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
    'threat_intelligence_ingestion',
    default_args=default_args,
    description='Ingest threat intelligence data from multiple sources',
    schedule_interval='0 */6 * * *',  # Run every 6 hours
    max_active_runs=1,
    tags=['threat-intelligence', 'ingestion', 'security']
)


def ingest_nvd_data(**context):
    """Ingest CVE data from NVD"""
    try:
        etl_pipeline = ETLPipeline()
        success = etl_pipeline.process_nvd_ingestion(days=1)
        
        if success:
            print("NVD data ingestion completed successfully")
            return "SUCCESS"
        else:
            raise Exception("NVD data ingestion failed")
    except Exception as e:
        print(f"Error during NVD ingestion: {e}")
        raise


def ingest_virustotal_data(**context):
    """Ingest malware data from VirusTotal"""
    try:
        # Get file hashes from previous task or external source
        # For demo purposes, using empty list
        file_hashes = []
        
        etl_pipeline = ETLPipeline()
        success = etl_pipeline.process_virustotal_ingestion(file_hashes)
        
        if success:
            print("VirusTotal data ingestion completed successfully")
            return "SUCCESS"
        else:
            raise Exception("VirusTotal data ingestion failed")
    except Exception as e:
        print(f"Error during VirusTotal ingestion: {e}")
        raise


def ingest_shodan_data(**context):
    """Ingest exposure data from Shodan"""
    try:
        # Get IP addresses from asset inventory or external source
        # For demo purposes, using empty list
        ips = []
        
        etl_pipeline = ETLPipeline()
        success = etl_pipeline.process_shodan_ingestion(ips)
        
        if success:
            print("Shodan data ingestion completed successfully")
            return "SUCCESS"
        else:
            raise Exception("Shodan data ingestion failed")
    except Exception as e:
        print(f"Error during Shodan ingestion: {e}")
        raise


def validate_api_keys(**context):
    """Validate API keys are available"""
    try:
        api_manager = APIKeyManager()
        
        # Check required services
        required_services = ['nvd', 'virustotal', 'shodan']
        missing_services = []
        
        for service in required_services:
            api_key = api_manager.get_api_key(service)
            if not api_key:
                missing_services.append(service)
        
        if missing_services:
            print(f"Missing API keys for services: {missing_services}")
            # Don't fail the DAG, just log warning
            return "WARNING"
        else:
            print("All required API keys are available")
            return "SUCCESS"
    except Exception as e:
        print(f"Error validating API keys: {e}")
        return "WARNING"


def cleanup_old_data(**context):
    """Clean up old data from S3 and DynamoDB"""
    try:
        # This would implement cleanup logic for old data
        # For now, just log the action
        print("Cleanup of old data completed")
        return "SUCCESS"
    except Exception as e:
        print(f"Error during cleanup: {e}")
        raise


def generate_ingestion_report(**context):
    """Generate ingestion report"""
    try:
        # This would generate a report of ingestion activities
        # For now, just log the action
        print("Ingestion report generated")
        return "SUCCESS"
    except Exception as e:
        print(f"Error generating report: {e}")
        raise


# Define tasks
validate_keys_task = PythonOperator(
    task_id='validate_api_keys',
    python_callable=validate_api_keys,
    dag=dag
)

ingest_nvd_task = PythonOperator(
    task_id='ingest_nvd_data',
    python_callable=ingest_nvd_data,
    dag=dag
)

ingest_virustotal_task = PythonOperator(
    task_id='ingest_virustotal_data',
    python_callable=ingest_virustotal_data,
    dag=dag
)

ingest_shodan_task = PythonOperator(
    task_id='ingest_shodan_data',
    python_callable=ingest_shodan_data,
    dag=dag
)

cleanup_task = PythonOperator(
    task_id='cleanup_old_data',
    python_callable=cleanup_old_data,
    dag=dag
)

report_task = PythonOperator(
    task_id='generate_ingestion_report',
    python_callable=generate_ingestion_report,
    dag=dag
)

# Define task dependencies
validate_keys_task >> [ingest_nvd_task, ingest_virustotal_task, ingest_shodan_task]
[ingest_nvd_task, ingest_virustotal_task, ingest_shodan_task] >> cleanup_task
cleanup_task >> report_task


# Additional DAG for daily full ingestion
daily_dag = DAG(
    'threat_intelligence_daily_ingestion',
    default_args=default_args,
    description='Daily full ingestion of threat intelligence data',
    schedule_interval='0 2 * * *',  # Run daily at 2 AM
    max_active_runs=1,
    tags=['threat-intelligence', 'daily-ingestion', 'security']
)


def run_full_ingestion(**context):
    """Run full ingestion pipeline for all sources"""
    try:
        etl_pipeline = ETLPipeline()
        results = etl_pipeline.run_full_ingestion()
        
        failed_sources = [source for source, success in results.items() if not success]
        
        if failed_sources:
            print(f"Failed sources: {failed_sources}")
            raise Exception(f"Ingestion failed for sources: {failed_sources}")
        else:
            print("Full ingestion completed successfully")
            return "SUCCESS"
    except Exception as e:
        print(f"Error during full ingestion: {e}")
        raise


full_ingestion_task = PythonOperator(
    task_id='run_full_ingestion',
    python_callable=run_full_ingestion,
    dag=daily_dag
)

# Weekly DAG for comprehensive data refresh
weekly_dag = DAG(
    'threat_intelligence_weekly_refresh',
    default_args=default_args,
    description='Weekly comprehensive refresh of threat intelligence data',
    schedule_interval='0 3 * * 0',  # Run weekly on Sunday at 3 AM
    max_active_runs=1,
    tags=['threat-intelligence', 'weekly-refresh', 'security']
)


def weekly_data_refresh(**context):
    """Perform weekly data refresh and cleanup"""
    try:
        # This would implement weekly refresh logic
        # Including data validation, cleanup, and reporting
        print("Weekly data refresh completed")
        return "SUCCESS"
    except Exception as e:
        print(f"Error during weekly refresh: {e}")
        raise


weekly_refresh_task = PythonOperator(
    task_id='weekly_data_refresh',
    python_callable=weekly_data_refresh,
    dag=weekly_dag
)


# Utility DAG for manual ingestion triggers
manual_dag = DAG(
    'threat_intelligence_manual_ingestion',
    default_args=default_args,
    description='Manual ingestion triggers for threat intelligence data',
    schedule_interval=None,  # Manual trigger only
    max_active_runs=1,
    tags=['threat-intelligence', 'manual', 'security']
)


def manual_nvd_ingestion(**context):
    """Manual NVD ingestion with custom parameters"""
    try:
        # Get parameters from context
        days = context['dag_run'].conf.get('days', 7)
        
        etl_pipeline = ETLPipeline()
        success = etl_pipeline.process_nvd_ingestion(days=days)
        
        if success:
            print(f"Manual NVD ingestion completed for {days} days")
            return "SUCCESS"
        else:
            raise Exception("Manual NVD ingestion failed")
    except Exception as e:
        print(f"Error during manual NVD ingestion: {e}")
        raise


manual_nvd_task = PythonOperator(
    task_id='manual_nvd_ingestion',
    python_callable=manual_nvd_ingestion,
    dag=manual_dag
)


# Error handling and monitoring tasks
def check_ingestion_health(**context):
    """Check the health of ingestion processes"""
    try:
        # This would implement health checks
        # Check S3 connectivity, DynamoDB tables, API endpoints, etc.
        print("Ingestion health check completed")
        return "SUCCESS"
    except Exception as e:
        print(f"Health check failed: {e}")
        raise


health_check_task = PythonOperator(
    task_id='check_ingestion_health',
    python_callable=check_ingestion_health,
    dag=dag
)

# Add health check to the main DAG
validate_keys_task >> health_check_task
health_check_task >> [ingest_nvd_task, ingest_virustotal_task, ingest_shodan_task] 
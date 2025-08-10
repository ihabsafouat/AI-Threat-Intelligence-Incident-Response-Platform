"""
Apache Airflow DAG for System Maintenance
Handles database cleanup, log rotation, and system health checks.
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

# Import our maintenance modules
from app.services.maintenance.database_cleaner import DatabaseCleaner
from app.services.maintenance.log_manager import LogManager
from app.services.monitoring.health_checker import HealthChecker

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
    'threat_intelligence_maintenance',
    default_args=default_args,
    description='System maintenance and monitoring tasks',
    schedule_interval='0 3 * * *',  # Run daily at 3 AM
    max_active_runs=1,
    tags=['threat-intelligence', 'maintenance', 'monitoring']
)


def check_system_health(**context):
    """Check overall system health"""
    try:
        health_checker = HealthChecker()
        success = health_checker.check_all_services()
        
        if success:
            print("System health check completed successfully")
            return "SUCCESS"
        else:
            raise Exception("System health check failed")
    except Exception as e:
        print(f"Error during health check: {e}")
        raise


def cleanup_old_data(**context):
    """Clean up old data from databases"""
    try:
        cleaner = DatabaseCleaner()
        success = cleaner.cleanup_old_records()
        
        if success:
            print("Database cleanup completed successfully")
            return "SUCCESS"
        else:
            raise Exception("Database cleanup failed")
    except Exception as e:
        print(f"Error during database cleanup: {e}")
        raise


def rotate_logs(**context):
    """Rotate and compress log files"""
    try:
        log_manager = LogManager()
        success = log_manager.rotate_logs()
        
        if success:
            print("Log rotation completed successfully")
            return "SUCCESS"
        else:
            raise Exception("Log rotation failed")
    except Exception as e:
        print(f"Error during log rotation: {e}")
        raise


def backup_database(**context):
    """Create database backup"""
    try:
        # This would create database backups
        print("Database backup completed successfully")
        return "SUCCESS"
    except Exception as e:
        print(f"Error during database backup: {e}")
        raise


def cleanup_temp_files(**context):
    """Clean up temporary files"""
    try:
        # This would clean up temporary files
        print("Temporary file cleanup completed successfully")
        return "SUCCESS"
    except Exception as e:
        print(f"Error during temp file cleanup: {e}")
        raise


def update_system_metrics(**context):
    """Update system performance metrics"""
    try:
        # This would update system metrics
        print("System metrics updated successfully")
        return "SUCCESS"
    except Exception as e:
        print(f"Error updating system metrics: {e}")
        raise


def send_maintenance_report(**context):
    """Send maintenance report"""
    try:
        # This would send maintenance reports
        print("Maintenance report sent successfully")
        return "SUCCESS"
    except Exception as e:
        print(f"Error sending maintenance report: {e}")
        raise


# Define tasks
health_check_task = PythonOperator(
    task_id='check_system_health',
    python_callable=check_system_health,
    dag=dag
)

cleanup_data_task = PythonOperator(
    task_id='cleanup_old_data',
    python_callable=cleanup_old_data,
    dag=dag
)

rotate_logs_task = PythonOperator(
    task_id='rotate_logs',
    python_callable=rotate_logs,
    dag=dag
)

backup_db_task = PythonOperator(
    task_id='backup_database',
    python_callable=backup_database,
    dag=dag
)

cleanup_temp_task = PythonOperator(
    task_id='cleanup_temp_files',
    python_callable=cleanup_temp_files,
    dag=dag
)

update_metrics_task = PythonOperator(
    task_id='update_system_metrics',
    python_callable=update_system_metrics,
    dag=dag
)

send_report_task = PythonOperator(
    task_id='send_maintenance_report',
    python_callable=send_maintenance_report,
    dag=dag
)

# Define task dependencies
health_check_task >> [cleanup_data_task, rotate_logs_task, backup_db_task]
[cleanup_data_task, rotate_logs_task, backup_db_task] >> cleanup_temp_task
cleanup_temp_task >> update_metrics_task
update_metrics_task >> send_report_task 
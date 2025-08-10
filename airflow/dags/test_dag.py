"""
Test DAG for Airflow Setup Verification
Simple DAG to test that Airflow is working correctly.
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator
from airflow.utils.dates import days_ago

# Default arguments for the DAG
default_args = {
    'owner': 'threat-intelligence-team',
    'depends_on_past': False,
    'start_date': days_ago(1),
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=1),
    'catchup': False
}

# Create the DAG
dag = DAG(
    'test_airflow_setup',
    default_args=default_args,
    description='Test DAG to verify Airflow setup',
    schedule_interval='@once',  # Run once manually
    max_active_runs=1,
    tags=['test', 'setup-verification']
)


def test_python_task(**context):
    """Test Python task execution"""
    print("Python task executed successfully!")
    print(f"Execution date: {context['execution_date']}")
    print(f"Task instance: {context['task_instance']}")
    return "SUCCESS"


def test_imports(**context):
    """Test that all required imports work"""
    try:
        import sys
        import os
        import requests
        import pandas as pd
        import numpy as np
        
        print("All imports successful!")
        print(f"Python version: {sys.version}")
        print(f"Working directory: {os.getcwd()}")
        return "SUCCESS"
    except ImportError as e:
        print(f"Import error: {e}")
        raise


def test_connections(**context):
    """Test database and Redis connections"""
    try:
        # Test database connection
        from sqlalchemy import create_engine
        engine = create_engine('postgresql://threat_user:threat_password@postgres:5432/threat_intel')
        with engine.connect() as conn:
            result = conn.execute("SELECT 1")
            print("Database connection successful!")
        
        # Test Redis connection
        import redis
        r = redis.Redis(host='redis', port=6379, decode_responses=True)
        r.ping()
        print("Redis connection successful!")
        
        return "SUCCESS"
    except Exception as e:
        print(f"Connection test failed: {e}")
        raise


# Define tasks
test_python = PythonOperator(
    task_id='test_python_task',
    python_callable=test_python_task,
    dag=dag
)

test_imports_task = PythonOperator(
    task_id='test_imports',
    python_callable=test_imports,
    dag=dag
)

test_connections_task = PythonOperator(
    task_id='test_connections',
    python_callable=test_connections,
    dag=dag
)

test_bash = BashOperator(
    task_id='test_bash_task',
    bash_command='echo "Bash task executed successfully!" && date',
    dag=dag
)

# Define task dependencies
test_python >> test_imports_task >> test_connections_task >> test_bash 
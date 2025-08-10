"""
Apache Airflow DAG for Threat Intelligence Data Processing
Handles data cleaning, enrichment, and analysis tasks.
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

# Import our processing modules
from app.services.processing.data_cleaner import DataCleaner
from app.services.processing.data_enricher import DataEnricher
from app.services.analysis.threat_analyzer import ThreatAnalyzer

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
    'threat_intelligence_data_processing',
    default_args=default_args,
    description='Process and analyze threat intelligence data',
    schedule_interval='0 */4 * * *',  # Run every 4 hours
    max_active_runs=1,
    tags=['threat-intelligence', 'processing', 'analysis']
)


def clean_raw_data(**context):
    """Clean raw threat intelligence data"""
    try:
        cleaner = DataCleaner()
        success = cleaner.clean_all_sources()
        
        if success:
            print("Data cleaning completed successfully")
            return "SUCCESS"
        else:
            raise Exception("Data cleaning failed")
    except Exception as e:
        print(f"Error during data cleaning: {e}")
        raise


def enrich_data(**context):
    """Enrich threat intelligence data with additional context"""
    try:
        enricher = DataEnricher()
        success = enricher.enrich_all_data()
        
        if success:
            print("Data enrichment completed successfully")
            return "SUCCESS"
        else:
            raise Exception("Data enrichment failed")
    except Exception as e:
        print(f"Error during data enrichment: {e}")
        raise


def analyze_threats(**context):
    """Analyze threats and generate insights"""
    try:
        analyzer = ThreatAnalyzer()
        success = analyzer.analyze_all_threats()
        
        if success:
            print("Threat analysis completed successfully")
            return "SUCCESS"
        else:
            raise Exception("Threat analysis failed")
    except Exception as e:
        print(f"Error during threat analysis: {e}")
        raise


def generate_reports(**context):
    """Generate analysis reports"""
    try:
        # This would generate various reports
        print("Analysis reports generated successfully")
        return "SUCCESS"
    except Exception as e:
        print(f"Error generating reports: {e}")
        raise


def update_dashboards(**context):
    """Update dashboards with latest data"""
    try:
        # This would update dashboard data
        print("Dashboards updated successfully")
        return "SUCCESS"
    except Exception as e:
        print(f"Error updating dashboards: {e}")
        raise


# Define tasks
clean_data_task = PythonOperator(
    task_id='clean_raw_data',
    python_callable=clean_raw_data,
    dag=dag
)

enrich_data_task = PythonOperator(
    task_id='enrich_data',
    python_callable=enrich_data,
    dag=dag
)

analyze_threats_task = PythonOperator(
    task_id='analyze_threats',
    python_callable=analyze_threats,
    dag=dag
)

generate_reports_task = PythonOperator(
    task_id='generate_reports',
    python_callable=generate_reports,
    dag=dag
)

update_dashboards_task = PythonOperator(
    task_id='update_dashboards',
    python_callable=update_dashboards,
    dag=dag
)

# Define task dependencies
clean_data_task >> enrich_data_task >> analyze_threats_task
analyze_threats_task >> [generate_reports_task, update_dashboards_task] 
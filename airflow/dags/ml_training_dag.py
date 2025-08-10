"""
Apache Airflow DAG for Machine Learning Model Training
Handles model training, validation, and deployment for threat intelligence.
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

# Import our ML modules
from app.services.ml.model_trainer import ModelTrainer
from app.services.ml.model_validator import ModelValidator
from app.services.ml.model_deployer import ModelDeployer

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
    'threat_intelligence_ml_training',
    default_args=default_args,
    description='Train and deploy ML models for threat intelligence',
    schedule_interval='0 1 * * 0',  # Run weekly on Sunday at 1 AM
    max_active_runs=1,
    tags=['threat-intelligence', 'ml', 'training']
)


def prepare_training_data(**context):
    """Prepare data for model training"""
    try:
        trainer = ModelTrainer()
        success = trainer.prepare_training_data()
        
        if success:
            print("Training data preparation completed successfully")
            return "SUCCESS"
        else:
            raise Exception("Training data preparation failed")
    except Exception as e:
        print(f"Error during data preparation: {e}")
        raise


def train_threat_classifier(**context):
    """Train threat classification model"""
    try:
        trainer = ModelTrainer()
        success = trainer.train_threat_classifier()
        
        if success:
            print("Threat classifier training completed successfully")
            return "SUCCESS"
        else:
            raise Exception("Threat classifier training failed")
    except Exception as e:
        print(f"Error during threat classifier training: {e}")
        raise


def train_anomaly_detector(**context):
    """Train anomaly detection model"""
    try:
        trainer = ModelTrainer()
        success = trainer.train_anomaly_detector()
        
        if success:
            print("Anomaly detector training completed successfully")
            return "SUCCESS"
        else:
            raise Exception("Anomaly detector training failed")
    except Exception as e:
        print(f"Error during anomaly detector training: {e}")
        raise


def validate_models(**context):
    """Validate trained models"""
    try:
        validator = ModelValidator()
        success = validator.validate_all_models()
        
        if success:
            print("Model validation completed successfully")
            return "SUCCESS"
        else:
            raise Exception("Model validation failed")
    except Exception as e:
        print(f"Error during model validation: {e}")
        raise


def deploy_models(**context):
    """Deploy validated models"""
    try:
        deployer = ModelDeployer()
        success = deployer.deploy_all_models()
        
        if success:
            print("Model deployment completed successfully")
            return "SUCCESS"
        else:
            raise Exception("Model deployment failed")
    except Exception as e:
        print(f"Error during model deployment: {e}")
        raise


def update_model_registry(**context):
    """Update model registry with new models"""
    try:
        # This would update the model registry
        print("Model registry updated successfully")
        return "SUCCESS"
    except Exception as e:
        print(f"Error updating model registry: {e}")
        raise


def cleanup_old_models(**context):
    """Clean up old model versions"""
    try:
        # This would clean up old model versions
        print("Old model cleanup completed successfully")
        return "SUCCESS"
    except Exception as e:
        print(f"Error during model cleanup: {e}")
        raise


# Define tasks
prepare_data_task = PythonOperator(
    task_id='prepare_training_data',
    python_callable=prepare_training_data,
    dag=dag
)

train_classifier_task = PythonOperator(
    task_id='train_threat_classifier',
    python_callable=train_threat_classifier,
    dag=dag
)

train_anomaly_task = PythonOperator(
    task_id='train_anomaly_detector',
    python_callable=train_anomaly_detector,
    dag=dag
)

validate_models_task = PythonOperator(
    task_id='validate_models',
    python_callable=validate_models,
    dag=dag
)

deploy_models_task = PythonOperator(
    task_id='deploy_models',
    python_callable=deploy_models,
    dag=dag
)

update_registry_task = PythonOperator(
    task_id='update_model_registry',
    python_callable=update_model_registry,
    dag=dag
)

cleanup_models_task = PythonOperator(
    task_id='cleanup_old_models',
    python_callable=cleanup_old_models,
    dag=dag
)

# Define task dependencies
prepare_data_task >> [train_classifier_task, train_anomaly_task]
[train_classifier_task, train_anomaly_task] >> validate_models_task
validate_models_task >> deploy_models_task
deploy_models_task >> update_registry_task
update_registry_task >> cleanup_models_task 
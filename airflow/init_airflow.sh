#!/bin/bash

# Airflow initialization script for Threat Intelligence Platform

set -e

echo "Initializing Airflow for Threat Intelligence Platform..."

# Set environment variables
export AIRFLOW_HOME=/opt/airflow
export AIRFLOW__CORE__EXECUTOR=LocalExecutor
export AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=postgresql+psycopg2://airflow:airflow@airflow-postgres:5432/airflow
export AIRFLOW__CORE__FERNET_KEY=''
export AIRFLOW__CORE__DAGS_ARE_PAUSED_AT_CREATION='true'
export AIRFLOW__CORE__LOAD_EXAMPLES='false'
export AIRFLOW__API__AUTH_BACKEND='airflow.api.auth.backend.basic_auth'
export AIRFLOW__WEBSERVER__SECRET_KEY='your-secret-key-change-in-production'
export AIRFLOW__CORE__DEFAULT_TIMEZONE='UTC'
export AIRFLOW__CORE__ENABLE_XCOM_PICKLING='true'

# Create necessary directories
mkdir -p /opt/airflow/dags
mkdir -p /opt/airflow/logs
mkdir -p /opt/airflow/plugins
mkdir -p /opt/airflow/config

# Wait for database to be ready
echo "Waiting for database to be ready..."
while ! nc -z airflow-postgres 5432; do
  sleep 1
done
echo "Database is ready!"

# Initialize the database
echo "Initializing Airflow database..."
airflow db init

# Create admin user
echo "Creating admin user..."
airflow users create \
    --username admin \
    --firstname Admin \
    --lastname User \
    --role Admin \
    --email admin@threatintel.com \
    --password admin123

# Create additional users
echo "Creating additional users..."
airflow users create \
    --username analyst \
    --firstname Threat \
    --lastname Analyst \
    --role User \
    --email analyst@threatintel.com \
    --password analyst123

airflow users create \
    --username operator \
    --firstname System \
    --lastname Operator \
    --role Op \
    --email operator@threatintel.com \
    --password operator123

# Set up connections
echo "Setting up Airflow connections..."

# Threat Intelligence API connections
airflow connections add 'threat_intelligence_nvd' \
    --conn-type 'http' \
    --conn-host 'https://services.nvd.nist.gov' \
    --conn-description 'NVD CVE Database API'

airflow connections add 'threat_intelligence_virustotal' \
    --conn-type 'http' \
    --conn-host 'https://www.virustotal.com' \
    --conn-password 'your-virustotal-api-key' \
    --conn-description 'VirusTotal API'

airflow connections add 'threat_intelligence_shodan' \
    --conn-type 'http' \
    --conn-host 'https://api.shodan.io' \
    --conn-password 'your-shodan-api-key' \
    --conn-description 'Shodan API'

# AWS connections
airflow connections add 'aws_default' \
    --conn-type 'aws' \
    --conn-login 'your-aws-access-key' \
    --conn-password 'your-aws-secret-key' \
    --conn-extra '{"region_name": "us-east-1"}' \
    --conn-description 'AWS Default Connection'

# Database connections
airflow connections add 'threat_intel_db' \
    --conn-type 'postgres' \
    --conn-host 'postgres' \
    --conn-login 'threat_user' \
    --conn-password 'threat_password' \
    --conn-schema 'threat_intel' \
    --conn-port '5432' \
    --conn-description 'Threat Intelligence Database'

# Redis connection
airflow connections add 'redis_default' \
    --conn-type 'redis' \
    --conn-host 'redis' \
    --conn-port '6379' \
    --conn-description 'Redis Cache'

# Set up variables
echo "Setting up Airflow variables..."
airflow variables set THREAT_INTEL_ENVIRONMENT production
airflow variables set THREAT_INTEL_VERSION 1.0.0
airflow variables set MAX_INGESTION_RETRIES 3
airflow variables set DATA_RETENTION_DAYS 90
airflow variables set ML_MODEL_UPDATE_FREQUENCY weekly

# Set up pools
echo "Setting up Airflow pools..."
airflow pools set ingestion_pool 10 "Pool for data ingestion tasks"
airflow pools set processing_pool 8 "Pool for data processing tasks"
airflow pools set ml_pool 4 "Pool for machine learning tasks"
airflow pools set maintenance_pool 2 "Pool for maintenance tasks"

# Unpause DAGs
echo "Unpausing DAGs..."
airflow dags unpause threat_intelligence_ingestion
airflow dags unpause threat_intelligence_data_processing
airflow dags unpause threat_intelligence_ml_training
airflow dags unpause threat_intelligence_maintenance

echo "Airflow initialization completed successfully!"
echo "You can now access the Airflow web interface at http://localhost:8080"
echo "Username: admin, Password: admin123" 
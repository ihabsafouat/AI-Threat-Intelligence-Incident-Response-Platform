# Apache Airflow for Threat Intelligence Platform

This directory contains the Apache Airflow configuration and DAGs for the Threat Intelligence Platform. Airflow orchestrates data ingestion, processing, analysis, and machine learning workflows.

## Directory Structure

```
airflow/
├── dags/                          # DAG definitions
│   ├── threat_intelligence_ingestion.py    # Data ingestion workflows
│   ├── data_processing_dag.py              # Data processing workflows
│   ├── ml_training_dag.py                  # ML model training workflows
│   └── maintenance_dag.py                  # System maintenance workflows
├── plugins/                       # Custom Airflow plugins
│   └── threat_intelligence_plugin.py       # Custom operators and hooks
├── logs/                          # Airflow logs
├── airflow.cfg                    # Airflow configuration
├── requirements.txt               # Python dependencies
├── init_airflow.sh               # Initialization script
└── README.md                     # This file
```

## DAGs Overview

### 1. Threat Intelligence Ingestion (`threat_intelligence_ingestion`)
- **Schedule**: Every 6 hours
- **Purpose**: Ingest data from various threat intelligence sources
- **Sources**: NVD, VirusTotal, Shodan
- **Tasks**:
  - Validate API keys
  - Ingest NVD CVE data
  - Ingest VirusTotal malware data
  - Ingest Shodan exposure data
  - Cleanup old data
  - Generate ingestion reports

### 2. Data Processing (`threat_intelligence_data_processing`)
- **Schedule**: Every 4 hours
- **Purpose**: Process and analyze threat intelligence data
- **Tasks**:
  - Clean raw data
  - Enrich data with additional context
  - Analyze threats and generate insights
  - Generate analysis reports
  - Update dashboards

### 3. ML Model Training (`threat_intelligence_ml_training`)
- **Schedule**: Weekly (Sunday at 1 AM)
- **Purpose**: Train and deploy machine learning models
- **Tasks**:
  - Prepare training data
  - Train threat classifier
  - Train anomaly detector
  - Validate models
  - Deploy models
  - Update model registry
  - Cleanup old models

### 4. System Maintenance (`threat_intelligence_maintenance`)
- **Schedule**: Daily at 3 AM
- **Purpose**: System maintenance and monitoring
- **Tasks**:
  - Check system health
  - Cleanup old data
  - Rotate logs
  - Backup database
  - Cleanup temporary files
  - Update system metrics
  - Send maintenance reports

## Custom Plugin

The `threat_intelligence_plugin.py` provides custom operators and hooks:

### Operators
- **ThreatIntelligenceOperator**: Generic operator for threat intelligence operations
- **ThreatIntelligenceSensor**: Sensor for monitoring data sources

### Hooks
- **ThreatIntelligenceHook**: Hook for API connections and requests

## Setup Instructions

### 1. Prerequisites
- Docker and Docker Compose installed
- Python 3.11+
- Required API keys for threat intelligence sources

### 2. Environment Variables
Set the following environment variables in your `.env` file:

```bash
# AWS Configuration
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_REGION=us-east-1
S3_BUCKET=your-s3-bucket

# API Keys
NVD_API_KEY=your-nvd-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
SHODAN_API_KEY=your-shodan-api-key
```

### 3. Start Airflow Services
```bash
# Start all services including Airflow
docker-compose up -d

# Initialize Airflow (first time only)
docker-compose run --rm airflow-init airflow db init
docker-compose run --rm airflow-init airflow users create \
    --username admin \
    --firstname Admin \
    --lastname User \
    --role Admin \
    --email admin@threatintel.com \
    --password admin123
```

### 4. Access Airflow Web UI
- URL: http://localhost:8080
- Username: admin
- Password: admin123

## DAG Management

### Manual DAG Triggers
You can manually trigger DAGs with custom parameters:

```bash
# Trigger ingestion with custom parameters
docker-compose run --rm airflow-webserver airflow dags trigger threat_intelligence_ingestion \
    --conf '{"days": 7, "sources": ["nvd", "virustotal"]}'

# Trigger ML training
docker-compose run --rm airflow-webserver airflow dags trigger threat_intelligence_ml_training
```

### DAG Monitoring
- Monitor DAG runs in the Airflow web UI
- Check logs for failed tasks
- Set up email notifications for failures
- Use Airflow's built-in monitoring and alerting

## Configuration

### Airflow Configuration (`airflow.cfg`)
Key configuration settings:
- **Executor**: LocalExecutor (for single-node deployment)
- **Database**: PostgreSQL
- **DAGs Folder**: `/opt/airflow/dags`
- **Logs Folder**: `/opt/airflow/logs`
- **Plugins Folder**: `/opt/airflow/plugins`

### Resource Pools
Configured pools for task distribution:
- **ingestion_pool**: 10 slots for data ingestion tasks
- **processing_pool**: 8 slots for data processing tasks
- **ml_pool**: 4 slots for machine learning tasks
- **maintenance_pool**: 2 slots for maintenance tasks

## Troubleshooting

### Common Issues

1. **DAGs not appearing**
   - Check if DAG files are in the correct directory
   - Verify Python syntax in DAG files
   - Check Airflow logs for import errors

2. **Tasks failing**
   - Check task logs in the Airflow web UI
   - Verify API keys and connections
   - Check database connectivity

3. **Performance issues**
   - Monitor resource usage
   - Adjust pool configurations
   - Optimize DAG schedules

### Logs
- Airflow logs: `airflow/logs/`
- Application logs: `logs/`
- Docker logs: `docker-compose logs airflow-webserver`

## Security Considerations

1. **API Keys**: Store API keys securely using Airflow connections
2. **Authentication**: Use strong passwords for Airflow users
3. **Network**: Restrict access to Airflow web UI in production
4. **Secrets**: Use Airflow's secrets backend for sensitive data

## Production Deployment

For production deployment:

1. **Use CeleryExecutor** for distributed task execution
2. **Set up external database** (RDS, Cloud SQL)
3. **Configure external secrets backend**
4. **Set up monitoring and alerting**
5. **Use reverse proxy** (Nginx) for web UI
6. **Enable SSL/TLS** for secure communication
7. **Set up backup and recovery procedures**

## Contributing

When adding new DAGs or modifying existing ones:

1. Follow the existing code structure
2. Add proper error handling
3. Include comprehensive logging
4. Test DAGs before deployment
5. Update documentation
6. Use appropriate task pools
7. Set reasonable retry policies

## Support

For issues and questions:
- Check Airflow documentation: https://airflow.apache.org/docs/
- Review task logs in the Airflow web UI
- Check system logs and Docker logs
- Consult the main project README for platform-wide issues 
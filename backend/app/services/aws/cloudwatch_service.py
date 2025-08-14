"""
CloudWatch Service Module

Handles monitoring, logging, and metrics in Amazon CloudWatch.
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Union
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import logging

from .config import AWSConfig

logger = logging.getLogger(__name__)


class CloudWatchService:
    """Amazon CloudWatch Service for monitoring and logging"""
    
    def __init__(self, config: AWSConfig, log_group_name: Optional[str] = None):
        """
        Initialize CloudWatch service.
        
        Args:
            config: AWS configuration
            log_group_name: CloudWatch log group name (defaults to environment variable)
        """
        self.config = config
        self.log_group_name = log_group_name or 'threat-intelligence-platform'
        self.cloudwatch_client = config.get_client('cloudwatch')
        self.logs_client = config.get_client('logs')
    
    def put_metric(
        self,
        metric_name: str,
        value: float,
        unit: str = 'Count',
        namespace: str = 'ThreatIntelligence',
        dimensions: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Put a custom metric to CloudWatch.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            unit: Metric unit (Count, Seconds, Bytes, etc.)
            namespace: Metric namespace
            dimensions: Metric dimensions
            
        Returns:
            Metric put result dictionary
        """
        try:
            metric_data = {
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit,
                'Timestamp': datetime.now(timezone.utc)
            }
            
            if dimensions:
                metric_data['Dimensions'] = dimensions
            
            self.cloudwatch_client.put_metric_data(
                Namespace=namespace,
                MetricData=[metric_data]
            )
            
            logger.info(f"Successfully put metric {metric_name} with value {value}")
            
            return {
                'success': True,
                'metric_name': metric_name,
                'value': value,
                'namespace': namespace
            }
            
        except Exception as e:
            logger.error(f"Failed to put metric: {e}")
            return {'success': False, 'error': str(e)}
    
    def put_threat_metric(
        self,
        threat_type: str,
        severity: str,
        count: int = 1,
        source: str = 'unknown'
    ) -> Dict[str, Any]:
        """
        Put threat intelligence metrics to CloudWatch.
        
        Args:
            threat_type: Type of threat
            severity: Threat severity
            count: Number of threats
            source: Threat source
            
        Returns:
            Metric put result dictionary
        """
        try:
            timestamp = datetime.now(timezone.utc)
            
            metric_data = [
                {
                    'MetricName': 'ThreatCount',
                    'Value': count,
                    'Unit': 'Count',
                    'Timestamp': timestamp,
                    'Dimensions': [
                        {'Name': 'ThreatType', 'Value': threat_type},
                        {'Name': 'Severity', 'Value': severity},
                        {'Name': 'Source', 'Value': source}
                    ]
                },
                {
                    'MetricName': 'ThreatSeverity',
                    'Value': self._severity_to_numeric(severity),
                    'Unit': 'None',
                    'Timestamp': timestamp,
                    'Dimensions': [
                        {'Name': 'ThreatType', 'Value': threat_type},
                        {'Name': 'Source', 'Value': source}
                    ]
                }
            ]
            
            self.cloudwatch_client.put_metric_data(
                Namespace='ThreatIntelligence',
                MetricData=metric_data
            )
            
            logger.info(f"Successfully put threat metrics for {threat_type} threats")
            
            return {
                'success': True,
                'threat_type': threat_type,
                'severity': severity,
                'count': count,
                'source': source
            }
            
        except Exception as e:
            logger.error(f"Failed to put threat metric: {e}")
            return {'success': False, 'error': str(e)}
    
    def _severity_to_numeric(self, severity: str) -> int:
        """Convert severity string to numeric value."""
        severity_map = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return severity_map.get(severity.lower(), 0)
    
    def log_event(
        self,
        message: str,
        log_stream_name: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Log an event to CloudWatch Logs.
        
        Args:
            message: Log message
            log_stream_name: Log stream name (auto-generated if not provided)
            additional_data: Additional data to include in log
            
        Returns:
            Log result dictionary
        """
        try:
            if not log_stream_name:
                log_stream_name = f"threat-intel-{datetime.now().strftime('%Y-%m-%d')}"
            
            # Create log stream if it doesn't exist
            try:
                self.logs_client.create_log_stream(
                    logGroupName=self.log_group_name,
                    logStreamName=log_stream_name
                )
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                    raise
            
            # Prepare log event
            log_event = {
                'timestamp': int(datetime.now(timezone.utc).timestamp() * 1000),
                'message': message
            }
            
            if additional_data:
                log_event.update(additional_data)
            
            # Put log event
            self.logs_client.put_log_events(
                logGroupName=self.log_group_name,
                logStreamName=log_stream_name,
                logEvents=[log_event]
            )
            
            logger.info(f"Successfully logged event to {self.log_group_name}/{log_stream_name}")
            
            return {
                'success': True,
                'log_group': self.log_group_name,
                'log_stream': log_stream_name,
                'message': message
            }
            
        except Exception as e:
            logger.error(f"Failed to log event: {e}")
            return {'success': False, 'error': str(e)}
    
    def log_threat_event(
        self,
        threat_id: str,
        event_type: str,
        description: str,
        severity: str = 'medium',
        additional_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Log a threat intelligence event to CloudWatch Logs.
        
        Args:
            threat_id: Threat identifier
            event_type: Type of event (detection, analysis, etc.)
            description: Event description
            severity: Event severity
            additional_data: Additional event data
            
        Returns:
            Log result dictionary
        """
        try:
            log_data = {
                'threat_id': threat_id,
                'event_type': event_type,
                'description': description,
                'severity': severity,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            if additional_data:
                log_data.update(additional_data)
            
            message = f"Threat Event: {event_type} - {description} (Threat ID: {threat_id}, Severity: {severity})"
            
            return self.log_event(message, additional_data=log_data)
            
        except Exception as e:
            logger.error(f"Failed to log threat event: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_metrics(
        self,
        metric_name: str,
        namespace: str = 'ThreatIntelligence',
        dimensions: Optional[List[Dict[str, str]]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        period: int = 300,
        statistic: str = 'Sum'
    ) -> Dict[str, Any]:
        """
        Get CloudWatch metrics.
        
        Args:
            metric_name: Name of the metric
            namespace: Metric namespace
            dimensions: Metric dimensions
            start_time: Start time for metric query
            end_time: End time for metric query
            period: Metric period in seconds
            statistic: Metric statistic (Sum, Average, etc.)
            
        Returns:
            Metrics data dictionary
        """
        try:
            if not start_time:
                start_time = datetime.now(timezone.utc) - timedelta(hours=1)
            if not end_time:
                end_time = datetime.now(timezone.utc)
            
            request_params = {
                'Namespace': namespace,
                'MetricName': metric_name,
                'StartTime': start_time,
                'EndTime': end_time,
                'Period': period,
                'Statistics': [statistic]
            }
            
            if dimensions:
                request_params['Dimensions'] = dimensions
            
            response = self.cloudwatch_client.get_metric_statistics(**request_params)
            
            return {
                'success': True,
                'metric_name': metric_name,
                'namespace': namespace,
                'datapoints': response.get('Datapoints', []),
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_threat_metrics(
        self,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get threat intelligence metrics.
        
        Args:
            threat_type: Filter by threat type
            severity: Filter by severity
            hours: Number of hours to look back
            
        Returns:
            Threat metrics dictionary
        """
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=hours)
            
            dimensions = []
            if threat_type:
                dimensions.append({'Name': 'ThreatType', 'Value': threat_type})
            if severity:
                dimensions.append({'Name': 'Severity', 'Value': severity})
            
            # Get threat count metrics
            count_metrics = self.get_metrics(
                'ThreatCount',
                dimensions=dimensions if dimensions else None,
                start_time=start_time,
                end_time=end_time,
                period=3600,  # 1 hour periods
                statistic='Sum'
            )
            
            # Get threat severity metrics
            severity_metrics = self.get_metrics(
                'ThreatSeverity',
                dimensions=dimensions if dimensions else None,
                start_time=start_time,
                end_time=end_time,
                period=3600,
                statistic='Average'
            )
            
            return {
                'success': True,
                'threat_type': threat_type,
                'severity': severity,
                'hours': hours,
                'count_metrics': count_metrics,
                'severity_metrics': severity_metrics
            }
            
        except Exception as e:
            logger.error(f"Failed to get threat metrics: {e}")
            return {'success': False, 'error': str(e)}
    
    def create_dashboard(
        self,
        dashboard_name: str,
        dashboard_body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create or update a CloudWatch dashboard.
        
        Args:
            dashboard_name: Name of the dashboard
            dashboard_body: Dashboard configuration
            
        Returns:
            Dashboard creation result dictionary
        """
        try:
            self.cloudwatch_client.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            
            logger.info(f"Successfully created/updated dashboard {dashboard_name}")
            
            return {
                'success': True,
                'dashboard_name': dashboard_name
            }
            
        except Exception as e:
            logger.error(f"Failed to create dashboard: {e}")
            return {'success': False, 'error': str(e)}
    
    def create_threat_dashboard(self, dashboard_name: str = 'ThreatIntelligence') -> Dict[str, Any]:
        """
        Create a threat intelligence dashboard.
        
        Args:
            dashboard_name: Name of the dashboard
            
        Returns:
            Dashboard creation result dictionary
        """
        try:
            dashboard_body = {
                'widgets': [
                    {
                        'type': 'metric',
                        'x': 0,
                        'y': 0,
                        'width': 12,
                        'height': 6,
                        'properties': {
                            'metrics': [
                                ['ThreatIntelligence', 'ThreatCount', 'ThreatType', 'malware'],
                                ['.', '.', 'ThreatType', 'phishing'],
                                ['.', '.', 'ThreatType', 'apt']
                            ],
                            'view': 'timeSeries',
                            'stacked': False,
                            'region': self.config.region,
                            'title': 'Threat Count by Type'
                        }
                    },
                    {
                        'type': 'metric',
                        'x': 12,
                        'y': 0,
                        'width': 12,
                        'height': 6,
                        'properties': {
                            'metrics': [
                                ['ThreatIntelligence', 'ThreatCount', 'Severity', 'critical'],
                                ['.', '.', 'Severity', 'high'],
                                ['.', '.', 'Severity', 'medium'],
                                ['.', '.', 'Severity', 'low']
                            ],
                            'view': 'timeSeries',
                            'stacked': False,
                            'region': self.config.region,
                            'title': 'Threat Count by Severity'
                        }
                    }
                ]
            }
            
            return self.create_dashboard(dashboard_name, dashboard_body)
            
        except Exception as e:
            logger.error(f"Failed to create threat dashboard: {e}")
            return {'success': False, 'error': str(e)}
    
    def set_alarm(
        self,
        alarm_name: str,
        metric_name: str,
        threshold: float,
        comparison_operator: str = 'GreaterThanThreshold',
        evaluation_periods: int = 1,
        period: int = 300,
        namespace: str = 'ThreatIntelligence',
        dimensions: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Create or update a CloudWatch alarm.
        
        Args:
            alarm_name: Name of the alarm
            metric_name: Name of the metric to monitor
            threshold: Alarm threshold
            comparison_operator: Comparison operator
            evaluation_periods: Number of evaluation periods
            period: Metric period in seconds
            namespace: Metric namespace
            dimensions: Metric dimensions
            
        Returns:
            Alarm creation result dictionary
        """
        try:
            alarm_params = {
                'AlarmName': alarm_name,
                'MetricName': metric_name,
                'Namespace': namespace,
                'Threshold': threshold,
                'ComparisonOperator': comparison_operator,
                'EvaluationPeriods': evaluation_periods,
                'Period': period,
                'Statistic': 'Sum'
            }
            
            if dimensions:
                alarm_params['Dimensions'] = dimensions
            
            self.cloudwatch_client.put_metric_alarm(**alarm_params)
            
            logger.info(f"Successfully created/updated alarm {alarm_name}")
            
            return {
                'success': True,
                'alarm_name': alarm_name,
                'metric_name': metric_name,
                'threshold': threshold
            }
            
        except Exception as e:
            logger.error(f"Failed to set alarm: {e}")
            return {'success': False, 'error': str(e)} 
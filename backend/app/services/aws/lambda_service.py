"""
Lambda Service Module

Handles AWS Lambda function integration for threat intelligence processing.
"""

import json
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Union
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import logging

from .config import AWSConfig

logger = logging.getLogger(__name__)


class LambdaService:
    """AWS Lambda Service for serverless function integration"""
    
    def __init__(self, config: AWSConfig):
        """
        Initialize Lambda service.
        
        Args:
            config: AWS configuration
        """
        self.config = config
        self.lambda_client = config.get_client('lambda')
    
    def invoke_function(
        self,
        function_name: str,
        payload: Optional[Dict[str, Any]] = None,
        invocation_type: str = 'RequestResponse',
        log_type: str = 'Tail'
    ) -> Dict[str, Any]:
        """
        Invoke a Lambda function.
        
        Args:
            function_name: Name of the Lambda function
            payload: Function payload data
            invocation_type: Invocation type (RequestResponse, Event, DryRun)
            log_type: Log type (None, Tail)
            
        Returns:
            Invocation result dictionary
        """
        try:
            invoke_params = {
                'FunctionName': function_name,
                'InvocationType': invocation_type
            }
            
            if payload:
                invoke_params['Payload'] = json.dumps(payload)
            
            if log_type != 'None':
                invoke_params['LogType'] = log_type
            
            response = self.lambda_client.invoke(**invoke_params)
            
            # Parse response
            result = {
                'success': True,
                'status_code': response['StatusCode'],
                'function_name': function_name
            }
            
            if 'Payload' in response:
                payload_data = response['Payload'].read()
                try:
                    result['payload'] = json.loads(payload_data.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    result['payload'] = payload_data.decode('utf-8', errors='ignore')
            
            if 'LogResult' in response:
                log_result = base64.b64decode(response['LogResult']).decode('utf-8')
                result['logs'] = log_result
            
            if 'ExecutedVersion' in response:
                result['executed_version'] = response['ExecutedVersion']
            
            logger.info(f"Successfully invoked Lambda function {function_name}")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to invoke Lambda function: {e}")
            return {'success': False, 'error': str(e)}
    
    def invoke_threat_analysis(
        self,
        threat_data: Dict[str, Any],
        analysis_type: str = 'basic'
    ) -> Dict[str, Any]:
        """
        Invoke threat analysis Lambda function.
        
        Args:
            threat_data: Threat data to analyze
            analysis_type: Type of analysis (basic, advanced, ml)
            
        Returns:
            Analysis result dictionary
        """
        try:
            payload = {
                'action': 'analyze_threat',
                'analysis_type': analysis_type,
                'threat_data': threat_data,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            function_name = f"threat-analysis-{analysis_type}"
            
            return self.invoke_function(function_name, payload)
            
        except Exception as e:
            logger.error(f"Failed to invoke threat analysis: {e}")
            return {'success': False, 'error': str(e)}
    
    def invoke_threat_enrichment(
        self,
        threat_indicators: List[str],
        enrichment_sources: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Invoke threat enrichment Lambda function.
        
        Args:
            threat_indicators: List of threat indicators (IPs, domains, hashes)
            enrichment_sources: List of enrichment sources to use
            
        Returns:
            Enrichment result dictionary
        """
        try:
            payload = {
                'action': 'enrich_threat',
                'indicators': threat_indicators,
                'sources': enrichment_sources or ['virustotal', 'abuseipdb', 'threatfox'],
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            function_name = 'threat-enrichment'
            
            return self.invoke_function(function_name, payload)
            
        except Exception as e:
            logger.error(f"Failed to invoke threat enrichment: {e}")
            return {'success': False, 'error': str(e)}
    
    def invoke_threat_correlation(
        self,
        threat_id: str,
        correlation_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Invoke threat correlation Lambda function.
        
        Args:
            threat_id: Threat identifier
            correlation_window_hours: Time window for correlation analysis
            
        Returns:
            Correlation result dictionary
        """
        try:
            payload = {
                'action': 'correlate_threat',
                'threat_id': threat_id,
                'correlation_window_hours': correlation_window_hours,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            function_name = 'threat-correlation'
            
            return self.invoke_function(function_name, payload)
            
        except Exception as e:
            logger.error(f"Failed to invoke threat correlation: {e}")
            return {'success': False, 'error': str(e)}
    
    def invoke_data_processing(
        self,
        data_source: str,
        processing_type: str = 'extract',
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Invoke data processing Lambda function.
        
        Args:
            data_source: Source of data to process
            processing_type: Type of processing (extract, transform, load)
            parameters: Additional processing parameters
            
        Returns:
            Processing result dictionary
        """
        try:
            payload = {
                'action': 'process_data',
                'data_source': data_source,
                'processing_type': processing_type,
                'parameters': parameters or {},
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            function_name = f"data-processing-{processing_type}"
            
            return self.invoke_function(function_name, payload)
            
        except Exception as e:
            logger.error(f"Failed to invoke data processing: {e}")
            return {'success': False, 'error': str(e)}
    
    def invoke_alert_generation(
        self,
        alert_data: Dict[str, Any],
        alert_type: str = 'standard'
    ) -> Dict[str, Any]:
        """
        Invoke alert generation Lambda function.
        
        Args:
            alert_data: Alert data
            alert_type: Type of alert (standard, critical, summary)
            
        Returns:
            Alert generation result dictionary
        """
        try:
            payload = {
                'action': 'generate_alert',
                'alert_type': alert_type,
                'alert_data': alert_data,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            function_name = f"alert-generation-{alert_type}"
            
            return self.invoke_function(function_name, payload)
            
        except Exception as e:
            logger.error(f"Failed to invoke alert generation: {e}")
            return {'success': False, 'error': str(e)}
    
    def list_functions(
        self,
        prefix: Optional[str] = None,
        max_items: int = 50
    ) -> Dict[str, Any]:
        """
        List Lambda functions.
        
        Args:
            prefix: Function name prefix filter
            max_items: Maximum number of functions to return
            
        Returns:
            Functions list dictionary
        """
        try:
            list_params = {
                'MaxItems': max_items
            }
            
            if prefix:
                list_params['FunctionVersion'] = 'ALL'
            
            response = self.lambda_client.list_functions(**list_params)
            
            functions = response.get('Functions', [])
            
            # Filter by prefix if provided
            if prefix:
                functions = [f for f in functions if f['FunctionName'].startswith(prefix)]
            
            return {
                'success': True,
                'functions': functions,
                'count': len(functions)
            }
            
        except Exception as e:
            logger.error(f"Failed to list Lambda functions: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_function_info(self, function_name: str) -> Dict[str, Any]:
        """
        Get Lambda function information.
        
        Args:
            function_name: Name of the Lambda function
            
        Returns:
            Function information dictionary
        """
        try:
            response = self.lambda_client.get_function(
                FunctionName=function_name
            )
            
            function_info = response['Configuration']
            
            return {
                'success': True,
                'function_name': function_info['FunctionName'],
                'runtime': function_info.get('Runtime'),
                'handler': function_info.get('Handler'),
                'code_size': function_info.get('CodeSize'),
                'description': function_info.get('Description'),
                'timeout': function_info.get('Timeout'),
                'memory_size': function_info.get('MemorySize'),
                'last_modified': function_info.get('LastModified'),
                'version': function_info.get('Version'),
                'environment': function_info.get('Environment', {}).get('Variables', {})
            }
            
        except Exception as e:
            logger.error(f"Failed to get function info: {e}")
            return {'success': False, 'error': str(e)}
    
    def update_function_configuration(
        self,
        function_name: str,
        environment_variables: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        memory_size: Optional[int] = None,
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update Lambda function configuration.
        
        Args:
            function_name: Name of the Lambda function
            environment_variables: Environment variables to update
            timeout: Function timeout in seconds
            memory_size: Function memory size in MB
            description: Function description
            
        Returns:
            Update result dictionary
        """
        try:
            update_params = {
                'FunctionName': function_name
            }
            
            if environment_variables is not None:
                update_params['Environment'] = {
                    'Variables': environment_variables
                }
            
            if timeout is not None:
                update_params['Timeout'] = timeout
            
            if memory_size is not None:
                update_params['MemorySize'] = memory_size
            
            if description is not None:
                update_params['Description'] = description
            
            self.lambda_client.update_function_configuration(**update_params)
            
            logger.info(f"Successfully updated Lambda function configuration {function_name}")
            
            return {
                'success': True,
                'function_name': function_name
            }
            
        except Exception as e:
            logger.error(f"Failed to update function configuration: {e}")
            return {'success': False, 'error': str(e)}
    
    def create_function(
        self,
        function_name: str,
        runtime: str,
        handler: str,
        role_arn: str,
        code_zip_path: str,
        description: Optional[str] = None,
        timeout: int = 30,
        memory_size: int = 128,
        environment_variables: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Create a new Lambda function.
        
        Args:
            function_name: Name of the Lambda function
            runtime: Function runtime (python3.9, nodejs18.x, etc.)
            handler: Function handler
            role_arn: IAM role ARN for the function
            code_zip_path: Path to the function code ZIP file
            description: Function description
            timeout: Function timeout in seconds
            memory_size: Function memory size in MB
            environment_variables: Environment variables
            
        Returns:
            Creation result dictionary
        """
        try:
            # Read the ZIP file
            with open(code_zip_path, 'rb') as zip_file:
                zip_content = zip_file.read()
            
            create_params = {
                'FunctionName': function_name,
                'Runtime': runtime,
                'Handler': handler,
                'Role': role_arn,
                'Code': {
                    'ZipFile': zip_content
                },
                'Timeout': timeout,
                'MemorySize': memory_size
            }
            
            if description:
                create_params['Description'] = description
            
            if environment_variables:
                create_params['Environment'] = {
                    'Variables': environment_variables
                }
            
            response = self.lambda_client.create_function(**create_params)
            
            logger.info(f"Successfully created Lambda function {function_name}")
            
            return {
                'success': True,
                'function_name': function_name,
                'function_arn': response['FunctionArn'],
                'runtime': response['Runtime'],
                'handler': response['Handler']
            }
            
        except Exception as e:
            logger.error(f"Failed to create Lambda function: {e}")
            return {'success': False, 'error': str(e)}
    
    def delete_function(self, function_name: str) -> Dict[str, Any]:
        """
        Delete a Lambda function.
        
        Args:
            function_name: Name of the Lambda function
            
        Returns:
            Deletion result dictionary
        """
        try:
            self.lambda_client.delete_function(
                FunctionName=function_name
            )
            
            logger.info(f"Successfully deleted Lambda function {function_name}")
            
            return {
                'success': True,
                'function_name': function_name
            }
            
        except Exception as e:
            logger.error(f"Failed to delete Lambda function: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_function_logs(
        self,
        function_name: str,
        log_group_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Get Lambda function logs from CloudWatch.
        
        Args:
            function_name: Name of the Lambda function
            log_group_name: CloudWatch log group name
            start_time: Start time for log query
            end_time: End time for log query
            limit: Maximum number of log events
            
        Returns:
            Logs result dictionary
        """
        try:
            if not log_group_name:
                log_group_name = f"/aws/lambda/{function_name}"
            
            if not start_time:
                start_time = datetime.now(timezone.utc) - timedelta(hours=1)
            if not end_time:
                end_time = datetime.now(timezone.utc)
            
            logs_client = self.config.get_client('logs')
            
            response = logs_client.filter_log_events(
                logGroupName=log_group_name,
                startTime=int(start_time.timestamp() * 1000),
                endTime=int(end_time.timestamp() * 1000),
                limit=limit
            )
            
            return {
                'success': True,
                'function_name': function_name,
                'log_group': log_group_name,
                'events': response.get('events', []),
                'count': len(response.get('events', []))
            }
            
        except Exception as e:
            logger.error(f"Failed to get function logs: {e}")
            return {'success': False, 'error': str(e)} 
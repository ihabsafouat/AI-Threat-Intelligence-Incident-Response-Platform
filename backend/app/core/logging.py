"""
API Logging System

Handles logging of all API requests and responses to CloudWatch and database.
"""

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union
from fastapi import Request, Response
from fastapi.responses import JSONResponse
import hashlib
import base64

from .config import settings
from app.services.aws import CloudWatchService, AWSConfig
from app.services.database.api_logging_service import api_logging_service


class APILogger:
    """Centralized API logging system"""
    
    def __init__(self):
        """Initialize the API logger"""
        self.logger = logging.getLogger(__name__)
        
        # Initialize CloudWatch service if AWS credentials are available
        self.cloudwatch_service = None
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            try:
                aws_config = AWSConfig.from_env()
                self.cloudwatch_service = CloudWatchService(aws_config)
                self.logger.info("CloudWatch logging enabled")
            except Exception as e:
                self.logger.warning(f"Failed to initialize CloudWatch service: {e}")
        
        # Database logging will be handled by the database service
        self.log_group_name = f"/aws/threat-intelligence/api-logs"
        self.log_stream_prefix = "api-requests"
        
        # Logging configuration
        self.enable_cloudwatch = getattr(settings, 'ENABLE_CLOUDWATCH_LOGGING', True)
        self.enable_database_logging = getattr(settings, 'ENABLE_DATABASE_LOGGING', True)
        self.log_sensitive_data = getattr(settings, 'LOG_SENSITIVE_DATA', False)
    
    def _generate_request_id(self) -> str:
        """Generate a unique request ID"""
        return str(uuid.uuid4())
    
    def _sanitize_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from logs"""
        if self.log_sensitive_data:
            return data
        
        sensitive_fields = {
            'password', 'token', 'secret', 'key', 'authorization',
            'api_key', 'access_token', 'refresh_token', 'private_key'
        }
        
        def sanitize_dict(obj: Any) -> Any:
            if isinstance(obj, dict):
                sanitized = {}
                for key, value in obj.items():
                    if any(sensitive in key.lower() for sensitive in sensitive_fields):
                        sanitized[key] = "***REDACTED***"
                    else:
                        sanitized[key] = sanitize_dict(value)
                return sanitized
            elif isinstance(obj, list):
                return [sanitize_dict(item) for item in obj]
            else:
                return obj
        
        return sanitize_dict(data)
    
    def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract relevant data from the request"""
        # Get request body if it's JSON
        body = None
        try:
            if request.headers.get("content-type", "").startswith("application/json"):
                body_bytes = request.body()
                if body_bytes:
                    body = json.loads(body_bytes.decode())
        except Exception:
            body = "***ERROR_PARSING_BODY***"
        
        # Get query parameters
        query_params = dict(request.query_params)
        
        # Get headers (excluding sensitive ones)
        headers = dict(request.headers)
        sensitive_headers = {'authorization', 'cookie', 'x-api-key'}
        for header in sensitive_headers:
            if header in headers:
                headers[header] = "***REDACTED***"
        
        return {
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "query_params": query_params,
            "headers": headers,
            "body": self._sanitize_sensitive_data(body) if body else None,
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "content_type": request.headers.get("content-type"),
            "content_length": request.headers.get("content-length")
        }
    
    def _extract_response_data(self, response: Response) -> Dict[str, Any]:
        """Extract relevant data from the response"""
        # Get response body if it's JSON
        body = None
        try:
            if hasattr(response, 'body') and response.body:
                if isinstance(response.body, bytes):
                    body = json.loads(response.body.decode())
                elif isinstance(response.body, str):
                    body = json.loads(response.body)
        except Exception:
            body = "***ERROR_PARSING_RESPONSE_BODY***"
        
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": self._sanitize_sensitive_data(body) if body else None,
            "content_type": response.headers.get("content-type"),
            "content_length": response.headers.get("content-length")
        }
    
    def _calculate_request_hash(self, request_data: Dict[str, Any]) -> str:
        """Calculate a hash for the request for deduplication"""
        # Create a string representation of the request
        request_str = f"{request_data['method']}:{request_data['path']}:{json.dumps(request_data['query_params'], sort_keys=True)}"
        if request_data['body']:
            request_str += f":{json.dumps(request_data['body'], sort_keys=True)}"
        
        return hashlib.md5(request_str.encode()).hexdigest()
    
    async def log_request(self, request: Request, request_id: str) -> Dict[str, Any]:
        """Log an incoming request"""
        start_time = time.time()
        request_data = self._extract_request_data(request)
        request_hash = self._calculate_request_hash(request_data)
        
        log_entry = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "api_request",
            "request_hash": request_hash,
            "request_data": request_data,
            "start_time": start_time
        }
        
        # Log to CloudWatch
        if self.enable_cloudwatch and self.cloudwatch_service:
            try:
                await self.cloudwatch_service.log_api_request(
                    request_id=request_id,
                    method=request_data['method'],
                    path=request_data['path'],
                    status_code=None,  # Not available yet
                    duration_ms=None,  # Not available yet
                    user_agent=request_data['user_agent'],
                    client_ip=request_data['client_ip'],
                    request_data=log_entry
                )
            except Exception as e:
                self.logger.error(f"Failed to log request to CloudWatch: {e}")
        
        # Log to database
        if self.enable_database_logging:
            try:
                await api_logging_service.log_request(log_entry)
            except Exception as e:
                self.logger.error(f"Failed to log request to database: {e}")
        
        # Log to application logs
        self.logger.info(f"API Request: {request_id} - {request_data['method']} {request_data['path']}")
        
        return log_entry
    
    async def log_response(self, request_id: str, response: Response, 
                          request_data: Dict[str, Any], start_time: float) -> Dict[str, Any]:
        """Log a response"""
        end_time = time.time()
        duration_ms = (end_time - start_time) * 1000
        
        response_data = self._extract_response_data(response)
        
        log_entry = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "api_response",
            "request_hash": request_data.get('request_hash'),
            "response_data": response_data,
            "duration_ms": round(duration_ms, 2),
            "start_time": start_time,
            "end_time": end_time
        }
        
        # Log to CloudWatch
        if self.enable_cloudwatch and self.cloudwatch_service:
            try:
                await self.cloudwatch_service.log_api_response(
                    request_id=request_id,
                    method=request_data['request_data']['method'],
                    path=request_data['request_data']['path'],
                    status_code=response_data['status_code'],
                    duration_ms=duration_ms,
                    user_agent=request_data['request_data']['user_agent'],
                    client_ip=request_data['request_data']['client_ip'],
                    response_data=log_entry
                )
            except Exception as e:
                self.logger.error(f"Failed to log response to CloudWatch: {e}")
        
        # Log to database
        if self.enable_database_logging:
            try:
                await api_logging_service.log_response(log_entry)
            except Exception as e:
                self.logger.error(f"Failed to log response to database: {e}")
        
        # Log to application logs
        log_level = logging.ERROR if response_data['status_code'] >= 400 else logging.INFO
        self.logger.log(
            log_level, 
            f"API Response: {request_id} - {response_data['status_code']} "
            f"({duration_ms:.2f}ms) - {request_data['request_data']['method']} "
            f"{request_data['request_data']['path']}"
        )
        
        return log_entry
    
    async def log_error(self, request_id: str, error: Exception, 
                       request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Log an error"""
        log_entry = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "api_error",
            "error_type": type(error).__name__,
            "error_message": str(error),
            "request_data": request_data
        }
        
        # Log to CloudWatch
        if self.enable_cloudwatch and self.cloudwatch_service:
            try:
                await self.cloudwatch_service.log_api_error(
                    request_id=request_id,
                    method=request_data['request_data']['method'],
                    path=request_data['request_data']['path'],
                    error_type=type(error).__name__,
                    error_message=str(error),
                    user_agent=request_data['request_data']['user_agent'],
                    client_ip=request_data['request_data']['client_ip'],
                    error_data=log_entry
                )
            except Exception as e:
                self.logger.error(f"Failed to log error to CloudWatch: {e}")
        
        # Log to database
        if self.enable_database_logging:
            try:
                await api_logging_service.log_error(log_entry)
            except Exception as e:
                self.logger.error(f"Failed to log error to database: {e}")
        
        # Log to application logs
        self.logger.error(
            f"API Error: {request_id} - {type(error).__name__}: {str(error)} - "
            f"{request_data['request_data']['method']} {request_data['request_data']['path']}"
        )
        
        return log_entry


# Global API logger instance
api_logger = APILogger() 
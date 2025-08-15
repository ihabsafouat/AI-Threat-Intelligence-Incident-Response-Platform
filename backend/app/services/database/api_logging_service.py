"""
API Logging Database Service

Handles storing and retrieving API logs from the database.
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc, asc
from sqlalchemy.sql import text

from app.models.api_logs import APILog, APIMetrics, APIPerformanceAlert
from app.core.database import get_db

logger = logging.getLogger(__name__)


class APILoggingService:
    """Service for managing API logs in the database"""
    
    def __init__(self):
        """Initialize the API logging service"""
        self.logger = logging.getLogger(__name__)
    
    async def log_request(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log an API request to the database.
        
        Args:
            log_data: Request log data
            
        Returns:
            Logging result dictionary
        """
        try:
            db = next(get_db())
            
            api_log = APILog(
                request_id=log_data['request_id'],
                session_id=log_data.get('session_id'),
                method=log_data['request_data']['method'],
                path=log_data['request_data']['path'],
                query_params=log_data['request_data']['query_params'],
                request_headers=log_data['request_data']['headers'],
                request_body=json.dumps(log_data['request_data']['body']) if log_data['request_data']['body'] else None,
                client_ip=log_data['request_data']['client_ip'],
                user_agent=log_data['request_data']['user_agent'],
                referer=log_data['request_data']['headers'].get('referer'),
                event_type='request',
                request_hash=log_data.get('request_hash'),
                request_size_bytes=log_data['request_data'].get('content_length'),
                tags=log_data.get('tags'),
                environment=log_data.get('environment', 'production')
            )
            
            db.add(api_log)
            db.commit()
            db.refresh(api_log)
            
            self.logger.info(f"Logged API request: {log_data['request_id']}")
            
            return {
                'success': True,
                'log_id': api_log.id,
                'request_id': log_data['request_id']
            }
            
        except Exception as e:
            self.logger.error(f"Failed to log API request: {e}")
            return {'success': False, 'error': str(e)}
    
    async def log_response(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log an API response to the database.
        
        Args:
            log_data: Response log data
            
        Returns:
            Logging result dictionary
        """
        try:
            db = next(get_db())
            
            api_log = APILog(
                request_id=log_data['request_id'],
                method=log_data['request_data']['request_data']['method'],
                path=log_data['request_data']['request_data']['path'],
                status_code=log_data['response_data']['status_code'],
                response_headers=log_data['response_data']['headers'],
                response_body=json.dumps(log_data['response_data']['body']) if log_data['response_data']['body'] else None,
                duration_ms=log_data['duration_ms'],
                response_size_bytes=log_data['response_data'].get('content_length'),
                client_ip=log_data['request_data']['request_data']['client_ip'],
                user_agent=log_data['request_data']['request_data']['user_agent'],
                event_type='response',
                request_hash=log_data.get('request_hash'),
                tags=log_data.get('tags'),
                environment=log_data.get('environment', 'production')
            )
            
            db.add(api_log)
            db.commit()
            db.refresh(api_log)
            
            # Update metrics
            await self._update_metrics(log_data)
            
            self.logger.info(f"Logged API response: {log_data['request_id']}")
            
            return {
                'success': True,
                'log_id': api_log.id,
                'request_id': log_data['request_id']
            }
            
        except Exception as e:
            self.logger.error(f"Failed to log API response: {e}")
            return {'success': False, 'error': str(e)}
    
    async def log_error(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log an API error to the database.
        
        Args:
            log_data: Error log data
            
        Returns:
            Logging result dictionary
        """
        try:
            db = next(get_db())
            
            api_log = APILog(
                request_id=log_data['request_id'],
                method=log_data['request_data']['request_data']['method'],
                path=log_data['request_data']['request_data']['path'],
                client_ip=log_data['request_data']['request_data']['client_ip'],
                user_agent=log_data['request_data']['request_data']['user_agent'],
                error_type=log_data['error_type'],
                error_message=log_data['error_message'],
                event_type='error',
                request_hash=log_data.get('request_hash'),
                tags=log_data.get('tags'),
                environment=log_data.get('environment', 'production')
            )
            
            db.add(api_log)
            db.commit()
            db.refresh(api_log)
            
            # Update error metrics
            await self._update_error_metrics(log_data)
            
            self.logger.info(f"Logged API error: {log_data['request_id']}")
            
            return {
                'success': True,
                'log_id': api_log.id,
                'request_id': log_data['request_id']
            }
            
        except Exception as e:
            self.logger.error(f"Failed to log API error: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _update_metrics(self, log_data: Dict[str, Any]) -> None:
        """Update API metrics"""
        try:
            db = next(get_db())
            
            # Get current time bucket (hourly)
            now = datetime.now(timezone.utc)
            time_period = now.replace(minute=0, second=0, microsecond=0)
            
            # Update request count
            await self._update_metric(
                db, 'api_requests', 1, 'Count',
                method=log_data['request_data']['request_data']['method'],
                path=log_data['request_data']['request_data']['path'],
                time_period=time_period
            )
            
            # Update response count
            await self._update_metric(
                db, 'api_responses', 1, 'Count',
                method=log_data['request_data']['request_data']['method'],
                path=log_data['request_data']['request_data']['path'],
                status_code=log_data['response_data']['status_code'],
                time_period=time_period
            )
            
            # Update duration metrics
            await self._update_metric(
                db, 'api_duration_avg', log_data['duration_ms'], 'Milliseconds',
                method=log_data['request_data']['request_data']['method'],
                path=log_data['request_data']['request_data']['path'],
                time_period=time_period
            )
            
        except Exception as e:
            self.logger.error(f"Failed to update metrics: {e}")
    
    async def _update_error_metrics(self, log_data: Dict[str, Any]) -> None:
        """Update error metrics"""
        try:
            db = next(get_db())
            
            # Get current time bucket (hourly)
            now = datetime.now(timezone.utc)
            time_period = now.replace(minute=0, second=0, microsecond=0)
            
            # Update error count
            await self._update_metric(
                db, 'api_errors', 1, 'Count',
                method=log_data['request_data']['request_data']['method'],
                path=log_data['request_data']['request_data']['path'],
                error_type=log_data['error_type'],
                time_period=time_period
            )
            
        except Exception as e:
            self.logger.error(f"Failed to update error metrics: {e}")
    
    async def _update_metric(
        self,
        db: Session,
        metric_name: str,
        value: float,
        unit: str,
        method: Optional[str] = None,
        path: Optional[str] = None,
        status_code: Optional[int] = None,
        error_type: Optional[str] = None,
        time_period: Optional[datetime] = None
    ) -> None:
        """Update a specific metric"""
        try:
            # Find existing metric
            query = db.query(APIMetrics).filter(
                and_(
                    APIMetrics.metric_name == metric_name,
                    APIMetrics.time_bucket == 'hour',
                    APIMetrics.time_period == time_period,
                    APIMetrics.method == method,
                    APIMetrics.path == path
                )
            )
            
            if status_code is not None:
                query = query.filter(APIMetrics.status_code == status_code)
            
            if error_type is not None:
                query = query.filter(APIMetrics.error_type == error_type)
            
            existing_metric = query.first()
            
            if existing_metric:
                # Update existing metric
                if metric_name == 'api_duration_avg':
                    # Calculate running average
                    current_count = existing_metric.metric_value
                    new_avg = ((existing_metric.metric_value * current_count) + value) / (current_count + 1)
                    existing_metric.metric_value = new_avg
                else:
                    existing_metric.metric_value += value
                
                existing_metric.updated_at = datetime.now(timezone.utc)
            else:
                # Create new metric
                new_metric = APIMetrics(
                    metric_name=metric_name,
                    metric_value=value,
                    metric_unit=unit,
                    method=method,
                    path=path,
                    status_code=status_code,
                    error_type=error_type,
                    time_bucket='hour',
                    time_period=time_period
                )
                db.add(new_metric)
            
            db.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to update metric {metric_name}: {e}")
    
    async def get_api_logs(
        self,
        request_id: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None,
        status_code: Optional[int] = None,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Retrieve API logs with filtering.
        
        Args:
            request_id: Filter by request ID
            method: Filter by HTTP method
            path: Filter by request path
            status_code: Filter by status code
            user_id: Filter by user ID
            organization_id: Filter by organization ID
            client_ip: Filter by client IP
            event_type: Filter by event type
            start_time: Start time filter
            end_time: End time filter
            limit: Maximum number of results
            offset: Offset for pagination
            
        Returns:
            API logs result dictionary
        """
        try:
            db = next(get_db())
            
            query = db.query(APILog)
            
            # Apply filters
            if request_id:
                query = query.filter(APILog.request_id == request_id)
            
            if method:
                query = query.filter(APILog.method == method)
            
            if path:
                query = query.filter(APILog.path.like(f"%{path}%"))
            
            if status_code:
                query = query.filter(APILog.status_code == status_code)
            
            if user_id:
                query = query.filter(APILog.user_id == user_id)
            
            if organization_id:
                query = query.filter(APILog.organization_id == organization_id)
            
            if client_ip:
                query = query.filter(APILog.client_ip == client_ip)
            
            if event_type:
                query = query.filter(APILog.event_type == event_type)
            
            if start_time:
                query = query.filter(APILog.created_at >= start_time)
            
            if end_time:
                query = query.filter(APILog.created_at <= end_time)
            
            # Get total count
            total_count = query.count()
            
            # Apply pagination and ordering
            logs = query.order_by(desc(APILog.created_at)).offset(offset).limit(limit).all()
            
            # Convert to dictionaries
            log_list = []
            for log in logs:
                log_dict = {
                    'id': log.id,
                    'request_id': log.request_id,
                    'method': log.method,
                    'path': log.path,
                    'status_code': log.status_code,
                    'duration_ms': log.duration_ms,
                    'client_ip': log.client_ip,
                    'user_agent': log.user_agent,
                    'event_type': log.event_type,
                    'error_type': log.error_type,
                    'error_message': log.error_message,
                    'created_at': log.created_at.isoformat() if log.created_at else None
                }
                log_list.append(log_dict)
            
            return {
                'success': True,
                'logs': log_list,
                'total_count': total_count,
                'limit': limit,
                'offset': offset
            }
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve API logs: {e}")
            return {'success': False, 'error': str(e)}
    
    async def get_api_metrics(
        self,
        metric_name: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None,
        time_bucket: str = 'hour',
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Retrieve API metrics.
        
        Args:
            metric_name: Filter by metric name
            method: Filter by HTTP method
            path: Filter by request path
            time_bucket: Time bucket (minute, hour, day)
            start_time: Start time filter
            end_time: End time filter
            limit: Maximum number of results
            
        Returns:
            API metrics result dictionary
        """
        try:
            db = next(get_db())
            
            query = db.query(APIMetrics)
            
            # Apply filters
            if metric_name:
                query = query.filter(APIMetrics.metric_name == metric_name)
            
            if method:
                query = query.filter(APIMetrics.method == method)
            
            if path:
                query = query.filter(APIMetrics.path.like(f"%{path}%"))
            
            query = query.filter(APIMetrics.time_bucket == time_bucket)
            
            if start_time:
                query = query.filter(APIMetrics.time_period >= start_time)
            
            if end_time:
                query = query.filter(APIMetrics.time_period <= end_time)
            
            # Get metrics
            metrics = query.order_by(desc(APIMetrics.time_period)).limit(limit).all()
            
            # Convert to dictionaries
            metric_list = []
            for metric in metrics:
                metric_dict = {
                    'id': metric.id,
                    'metric_name': metric.metric_name,
                    'metric_value': metric.metric_value,
                    'metric_unit': metric.metric_unit,
                    'method': metric.method,
                    'path': metric.path,
                    'status_code': metric.status_code,
                    'error_type': metric.error_type,
                    'time_bucket': metric.time_bucket,
                    'time_period': metric.time_period.isoformat() if metric.time_period else None,
                    'created_at': metric.created_at.isoformat() if metric.created_at else None
                }
                metric_list.append(metric_dict)
            
            return {
                'success': True,
                'metrics': metric_list,
                'count': len(metric_list)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve API metrics: {e}")
            return {'success': False, 'error': str(e)}
    
    async def cleanup_old_logs(self, days_to_keep: int = 30) -> Dict[str, Any]:
        """
        Clean up old API logs.
        
        Args:
            days_to_keep: Number of days to keep logs
            
        Returns:
            Cleanup result dictionary
        """
        try:
            db = next(get_db())
            
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
            
            # Delete old logs
            deleted_count = db.query(APILog).filter(
                APILog.created_at < cutoff_date
            ).delete()
            
            db.commit()
            
            self.logger.info(f"Cleaned up {deleted_count} old API logs")
            
            return {
                'success': True,
                'deleted_count': deleted_count,
                'cutoff_date': cutoff_date.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old logs: {e}")
            return {'success': False, 'error': str(e)}


# Global API logging service instance
api_logging_service = APILoggingService() 
"""
API Logs Endpoints

Endpoints for viewing and managing API logs.
"""

from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from app.services.database.api_logging_service import api_logging_service
from app.core.auth import get_current_user
from app.schemas.user import User

router = APIRouter()


@router.get("/api-logs")
async def get_api_logs(
    request_id: Optional[str] = Query(None, description="Filter by request ID"),
    method: Optional[str] = Query(None, description="Filter by HTTP method"),
    path: Optional[str] = Query(None, description="Filter by request path"),
    status_code: Optional[int] = Query(None, description="Filter by status code"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    organization_id: Optional[str] = Query(None, description="Filter by organization ID"),
    client_ip: Optional[str] = Query(None, description="Filter by client IP"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    start_time: Optional[str] = Query(None, description="Start time (ISO format)"),
    end_time: Optional[str] = Query(None, description="End time (ISO format)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve API logs with filtering and pagination.
    
    Requires authentication and appropriate permissions.
    """
    try:
        # Parse datetime strings
        start_dt = None
        end_dt = None
        
        if start_time:
            try:
                start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid start_time format")
        
        if end_time:
            try:
                end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid end_time format")
        
        # Get logs from database
        result = await api_logging_service.get_api_logs(
            request_id=request_id,
            method=method,
            path=path,
            status_code=status_code,
            user_id=user_id,
            organization_id=organization_id,
            client_ip=client_ip,
            event_type=event_type,
            start_time=start_dt,
            end_time=end_dt,
            limit=limit,
            offset=offset
        )
        
        if not result['success']:
            raise HTTPException(status_code=500, detail=result['error'])
        
        return {
            "success": True,
            "data": result['logs'],
            "pagination": {
                "total_count": result['total_count'],
                "limit": result['limit'],
                "offset": result['offset'],
                "has_more": (result['offset'] + result['limit']) < result['total_count']
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve API logs: {str(e)}")


@router.get("/api-metrics")
async def get_api_metrics(
    metric_name: Optional[str] = Query(None, description="Filter by metric name"),
    method: Optional[str] = Query(None, description="Filter by HTTP method"),
    path: Optional[str] = Query(None, description="Filter by request path"),
    time_bucket: str = Query("hour", description="Time bucket (minute, hour, day)"),
    start_time: Optional[str] = Query(None, description="Start time (ISO format)"),
    end_time: Optional[str] = Query(None, description="End time (ISO format)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve API metrics with filtering.
    
    Requires authentication and appropriate permissions.
    """
    try:
        # Parse datetime strings
        start_dt = None
        end_dt = None
        
        if start_time:
            try:
                start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid start_time format")
        
        if end_time:
            try:
                end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid end_time format")
        
        # Get metrics from database
        result = await api_logging_service.get_api_metrics(
            metric_name=metric_name,
            method=method,
            path=path,
            time_bucket=time_bucket,
            start_time=start_dt,
            end_time=end_dt,
            limit=limit
        )
        
        if not result['success']:
            raise HTTPException(status_code=500, detail=result['error'])
        
        return {
            "success": True,
            "data": result['metrics'],
            "count": result['count']
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve API metrics: {str(e)}")


@router.get("/api-logs/summary")
async def get_api_logs_summary(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    current_user: User = Depends(get_current_user)
):
    """
    Get a summary of API logs for the specified time period.
    
    Requires authentication and appropriate permissions.
    """
    try:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        # Get logs for the time period
        logs_result = await api_logging_service.get_api_logs(
            start_time=start_time,
            end_time=end_time,
            limit=10000  # Get all logs for summary
        )
        
        if not logs_result['success']:
            raise HTTPException(status_code=500, detail=logs_result['error'])
        
        logs = logs_result['logs']
        
        # Calculate summary statistics
        total_requests = len([log for log in logs if log['event_type'] == 'request'])
        total_responses = len([log for log in logs if log['event_type'] == 'response'])
        total_errors = len([log for log in logs if log['event_type'] == 'error'])
        
        # Status code distribution
        status_codes = {}
        for log in logs:
            if log['status_code']:
                status_codes[log['status_code']] = status_codes.get(log['status_code'], 0) + 1
        
        # Method distribution
        methods = {}
        for log in logs:
            if log['method']:
                methods[log['method']] = methods.get(log['method'], 0) + 1
        
        # Path distribution (top 10)
        paths = {}
        for log in logs:
            if log['path']:
                paths[log['path']] = paths.get(log['path'], 0) + 1
        
        top_paths = sorted(paths.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Average response time
        response_times = [log['duration_ms'] for log in logs if log['duration_ms']]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Error rate
        error_rate = (total_errors / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "success": True,
            "summary": {
                "time_period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "hours": hours
                },
                "total_requests": total_requests,
                "total_responses": total_responses,
                "total_errors": total_errors,
                "error_rate_percent": round(error_rate, 2),
                "avg_response_time_ms": round(avg_response_time, 2),
                "status_code_distribution": status_codes,
                "method_distribution": methods,
                "top_paths": dict(top_paths)
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate API logs summary: {str(e)}")


@router.delete("/api-logs/cleanup")
async def cleanup_old_logs(
    days_to_keep: int = Query(30, ge=1, le=365, description="Number of days to keep logs"),
    current_user: User = Depends(get_current_user)
):
    """
    Clean up old API logs.
    
    Requires authentication and appropriate permissions.
    """
    try:
        result = await api_logging_service.cleanup_old_logs(days_to_keep)
        
        if not result['success']:
            raise HTTPException(status_code=500, detail=result['error'])
        
        return {
            "success": True,
            "message": f"Successfully cleaned up {result['deleted_count']} old API logs",
            "deleted_count": result['deleted_count'],
            "cutoff_date": result['cutoff_date']
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cleanup old logs: {str(e)}")


@router.get("/api-logs/request/{request_id}")
async def get_request_logs(
    request_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get all logs for a specific request ID.
    
    Requires authentication and appropriate permissions.
    """
    try:
        result = await api_logging_service.get_api_logs(
            request_id=request_id,
            limit=100
        )
        
        if not result['success']:
            raise HTTPException(status_code=500, detail=result['error'])
        
        if not result['logs']:
            raise HTTPException(status_code=404, detail="Request logs not found")
        
        return {
            "success": True,
            "request_id": request_id,
            "logs": result['logs']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve request logs: {str(e)}") 
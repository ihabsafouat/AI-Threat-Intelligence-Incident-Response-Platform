"""
FastAPI Logging Middleware

Middleware to log all API requests and responses.
"""

import time
import json
from typing import Callable
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.logging import api_logger


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all API requests and responses"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request and log it"""
        # Generate unique request ID
        request_id = api_logger._generate_request_id()
        
        # Add request ID to request state
        request.state.request_id = request_id
        
        # Log the incoming request
        request_data = None
        start_time = None
        
        try:
            request_data = await api_logger.log_request(request, request_id)
            start_time = request_data['start_time']
            
            # Process the request
            response = await call_next(request)
            
            # Log the response
            await api_logger.log_response(request_id, response, request_data, start_time)
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as e:
            # Log the error
            if request_data:
                await api_logger.log_error(request_id, e, request_data)
            
            # Return error response
            error_response = JSONResponse(
                status_code=500,
                content={
                    "error": "Internal server error",
                    "request_id": request_id,
                    "message": "An unexpected error occurred"
                }
            )
            error_response.headers["X-Request-ID"] = request_id
            
            return error_response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware to add request ID to all requests"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add request ID to request state"""
        # Check if request ID is already in headers
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = api_logger._generate_request_id()
        
        # Add to request state
        request.state.request_id = request_id
        
        # Process request
        response = await call_next(request)
        
        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id
        
        return response


class PerformanceMiddleware(BaseHTTPMiddleware):
    """Middleware to track API performance metrics"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Track performance metrics"""
        start_time = time.time()
        
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Add performance headers
        response.headers["X-Response-Time"] = f"{duration:.3f}s"
        
        # Log slow requests (over 1 second)
        if duration > 1.0:
            request_id = getattr(request.state, 'request_id', 'unknown')
            api_logger.logger.warning(
                f"Slow request detected: {request_id} - {request.method} {request.url.path} "
                f"took {duration:.3f}s"
            )
        
        return response 
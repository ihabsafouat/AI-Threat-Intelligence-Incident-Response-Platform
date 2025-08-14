"""
RBAC Middleware

FastAPI middleware for handling authentication and authorization.
"""

import time
from typing import Optional, Callable
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging

from .auth import get_rbac_auth, RBACAuth
from .models import User

logger = logging.getLogger(__name__)


class RBACMiddleware(BaseHTTPMiddleware):
    """RBAC middleware for FastAPI applications."""
    
    def __init__(
        self,
        app: ASGIApp,
        exclude_paths: Optional[list] = None,
        public_paths: Optional[list] = None,
        auth_header: str = "Authorization",
        token_prefix: str = "Bearer"
    ):
        super().__init__(app)
        self.exclude_paths = exclude_paths or [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/metrics"
        ]
        self.public_paths = public_paths or [
            "/auth/login",
            "/auth/register",
            "/auth/refresh"
        ]
        self.auth_header = auth_header
        self.token_prefix = token_prefix
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request through the RBAC middleware."""
        start_time = time.time()
        
        # Skip authentication for excluded paths
        if self._is_excluded_path(request.url.path):
            return await call_next(request)
        
        # Handle public paths (no authentication required)
        if self._is_public_path(request.url.path):
            return await call_next(request)
        
        # Extract and validate authentication token
        user = await self._authenticate_request(request)
        if user:
            request.state.current_user = user
            request.state.authenticated = True
        else:
            request.state.current_user = None
            request.state.authenticated = False
        
        # Process the request
        try:
            response = await call_next(request)
            
            # Add authentication headers
            if user:
                response.headers["X-User-ID"] = str(user.id)
                response.headers["X-User-Username"] = user.username
                response.headers["X-User-Roles"] = ",".join([role.name for role in user.roles])
            
            # Add timing information
            process_time = time.time() - start_time
            response.headers["X-Process-Time"] = str(process_time)
            
            return response
            
        except HTTPException as e:
            # Log authentication/authorization errors
            if e.status_code in [401, 403]:
                logger.warning(
                    f"Auth error: {e.status_code} - {e.detail} - "
                    f"Path: {request.url.path} - "
                    f"Method: {request.method} - "
                    f"User: {getattr(user, 'username', 'anonymous') if user else 'anonymous'}"
                )
            raise
        except Exception as e:
            logger.error(f"Middleware error: {str(e)} - Path: {request.url.path}")
            raise
    
    def _is_excluded_path(self, path: str) -> bool:
        """Check if the path should be excluded from middleware processing."""
        return any(path.startswith(exclude_path) for exclude_path in self.exclude_paths)
    
    def _is_public_path(self, path: str) -> bool:
        """Check if the path is public (no authentication required)."""
        return any(path.startswith(public_path) for public_path in self.public_paths)
    
    async def _authenticate_request(self, request: Request) -> Optional[User]:
        """Authenticate the request and return the user if valid."""
        try:
            # Extract token from header
            auth_header = request.headers.get(self.auth_header)
            if not auth_header:
                return None
            
            if not auth_header.startswith(f"{self.token_prefix} "):
                return None
            
            token = auth_header[len(f"{self.token_prefix} "):]
            if not token:
                return None
            
            # Get database session (this should be injected by your dependency)
            db = getattr(request.state, 'db', None)
            if not db:
                logger.warning("Database session not found in request state")
                return None
            
            # Authenticate token
            rbac_auth = get_rbac_auth(db)
            user = rbac_auth.get_current_user_from_token(token)
            
            return user
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None


class AuditMiddleware(BaseHTTPMiddleware):
    """Audit middleware for logging user actions."""
    
    def __init__(self, app: ASGIApp, log_sensitive_paths: bool = False):
        super().__init__(app)
        self.log_sensitive_paths = log_sensitive_paths
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request and log audit information."""
        start_time = time.time()
        
        # Get user information
        user = getattr(request.state, 'current_user', None)
        user_id = user.id if user else None
        username = user.username if user else 'anonymous'
        
        # Log request
        self._log_request(request, username, user_id)
        
        # Process request
        response = await call_next(request)
        
        # Log response
        process_time = time.time() - start_time
        self._log_response(request, response, username, user_id, process_time)
        
        return response
    
    def _log_request(self, request: Request, username: str, user_id: Optional[int]):
        """Log request information."""
        log_data = {
            "event": "request",
            "method": request.method,
            "path": request.url.path,
            "query_params": str(request.query_params),
            "user_id": user_id,
            "username": username,
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "timestamp": time.time()
        }
        
        # Log sensitive operations
        if self._is_sensitive_operation(request):
            logger.info(f"Sensitive operation: {log_data}")
        else:
            logger.debug(f"Request: {log_data}")
    
    def _log_response(self, request: Request, response: Response, username: str, user_id: Optional[int], process_time: float):
        """Log response information."""
        log_data = {
            "event": "response",
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "user_id": user_id,
            "username": username,
            "process_time": process_time,
            "timestamp": time.time()
        }
        
        # Log errors and sensitive operations
        if response.status_code >= 400 or self._is_sensitive_operation(request):
            logger.info(f"Response: {log_data}")
        else:
            logger.debug(f"Response: {log_data}")
    
    def _is_sensitive_operation(self, request: Request) -> bool:
        """Check if the operation is sensitive and should be logged."""
        sensitive_paths = [
            "/auth/",
            "/users/",
            "/roles/",
            "/permissions/",
            "/admin/",
            "/system/"
        ]
        
        sensitive_methods = ["POST", "PUT", "DELETE", "PATCH"]
        
        return (
            any(request.url.path.startswith(path) for path in sensitive_paths) or
            request.method in sensitive_methods
        )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware for API endpoints."""
    
    def __init__(self, app: ASGIApp, rate_limit: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.rate_limit = rate_limit
        self.window_seconds = window_seconds
        self.request_counts = {}
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request with rate limiting."""
        # Get client identifier
        client_id = self._get_client_id(request)
        
        # Check rate limit
        if not self._check_rate_limit(client_id):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": self.window_seconds
                },
                headers={"Retry-After": str(self.window_seconds)}
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.rate_limit)
        response.headers["X-RateLimit-Remaining"] = str(self._get_remaining_requests(client_id))
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + self.window_seconds)
        
        return response
    
    def _get_client_id(self, request: Request) -> str:
        """Get a unique identifier for the client."""
        # Use user ID if authenticated, otherwise use IP
        user = getattr(request.state, 'current_user', None)
        if user:
            return f"user_{user.id}"
        else:
            return f"ip_{request.client.host}" if request.client else "unknown"
    
    def _check_rate_limit(self, client_id: str) -> bool:
        """Check if the client has exceeded the rate limit."""
        current_time = time.time()
        window_start = current_time - self.window_seconds
        
        # Clean old entries
        if client_id in self.request_counts:
            self.request_counts[client_id] = [
                timestamp for timestamp in self.request_counts[client_id]
                if timestamp > window_start
            ]
        else:
            self.request_counts[client_id] = []
        
        # Check if limit exceeded
        if len(self.request_counts[client_id]) >= self.rate_limit:
            return False
        
        # Add current request
        self.request_counts[client_id].append(current_time)
        return True
    
    def _get_remaining_requests(self, client_id: str) -> int:
        """Get the number of remaining requests for the client."""
        if client_id not in self.request_counts:
            return self.rate_limit
        
        current_time = time.time()
        window_start = current_time - self.window_seconds
        
        # Count requests in current window
        requests_in_window = len([
            timestamp for timestamp in self.request_counts[client_id]
            if timestamp > window_start
        ])
        
        return max(0, self.rate_limit - requests_in_window)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to responses."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add security headers to the response."""
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response


def setup_rbac_middleware(app: ASGIApp, **kwargs) -> None:
    """Setup RBAC middleware for the FastAPI application."""
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, **kwargs)
    app.add_middleware(AuditMiddleware)
    app.add_middleware(RBACMiddleware, **kwargs) 
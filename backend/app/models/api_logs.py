"""
API Logs Database Models

Database models for storing API request/response logs.
"""

from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON, Boolean, Index
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class APILog(Base):
    """API Log model for storing request/response logs"""
    
    __tablename__ = "api_logs"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True)
    
    # Request identification
    request_id = Column(String(36), nullable=False, index=True)  # UUID
    session_id = Column(String(36), nullable=True, index=True)   # Session ID if available
    
    # Request details
    method = Column(String(10), nullable=False, index=True)      # GET, POST, PUT, DELETE, etc.
    path = Column(String(500), nullable=False, index=True)       # Request path
    query_params = Column(JSON, nullable=True)                   # Query parameters
    request_headers = Column(JSON, nullable=True)                # Request headers (sanitized)
    request_body = Column(Text, nullable=True)                   # Request body (sanitized)
    
    # Response details
    status_code = Column(Integer, nullable=True, index=True)     # HTTP status code
    response_headers = Column(JSON, nullable=True)               # Response headers
    response_body = Column(Text, nullable=True)                  # Response body (sanitized)
    
    # Performance metrics
    duration_ms = Column(Float, nullable=True, index=True)       # Request duration in milliseconds
    request_size_bytes = Column(Integer, nullable=True)          # Request size in bytes
    response_size_bytes = Column(Integer, nullable=True)         # Response size in bytes
    
    # Client information
    client_ip = Column(String(45), nullable=True, index=True)    # Client IP address
    user_agent = Column(String(500), nullable=True)              # User agent string
    referer = Column(String(500), nullable=True)                 # Referer header
    
    # Authentication and user context
    user_id = Column(String(36), nullable=True, index=True)      # User ID if authenticated
    organization_id = Column(String(36), nullable=True, index=True)  # Organization ID
    api_key_id = Column(String(36), nullable=True, index=True)   # API key ID if used
    
    # Error information
    error_type = Column(String(100), nullable=True, index=True)  # Type of error
    error_message = Column(Text, nullable=True)                  # Error message
    stack_trace = Column(Text, nullable=True)                    # Stack trace if available
    
    # Metadata
    event_type = Column(String(20), nullable=False, index=True)  # request, response, error
    request_hash = Column(String(32), nullable=True, index=True) # MD5 hash for deduplication
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Additional context
    tags = Column(JSON, nullable=True)                           # Additional tags/metadata
    environment = Column(String(20), nullable=True, index=True)  # dev, staging, prod
    
    # Indexes for better query performance
    __table_args__ = (
        Index('idx_api_logs_request_id_created', 'request_id', 'created_at'),
        Index('idx_api_logs_method_path', 'method', 'path'),
        Index('idx_api_logs_status_code', 'status_code'),
        Index('idx_api_logs_user_id_created', 'user_id', 'created_at'),
        Index('idx_api_logs_organization_created', 'organization_id', 'created_at'),
        Index('idx_api_logs_client_ip_created', 'client_ip', 'created_at'),
    )


class APIMetrics(Base):
    """API Metrics model for storing aggregated metrics"""
    
    __tablename__ = "api_metrics"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True)
    
    # Metric identification
    metric_name = Column(String(100), nullable=False, index=True)  # requests, responses, errors, duration
    metric_value = Column(Float, nullable=False)                   # Metric value
    metric_unit = Column(String(20), nullable=False)               # Count, Milliseconds, Bytes, etc.
    
    # Dimensions
    method = Column(String(10), nullable=True, index=True)         # HTTP method
    path = Column(String(500), nullable=True, index=True)          # Request path
    status_code = Column(Integer, nullable=True, index=True)       # HTTP status code
    error_type = Column(String(100), nullable=True, index=True)    # Error type
    user_id = Column(String(36), nullable=True, index=True)        # User ID
    organization_id = Column(String(36), nullable=True, index=True) # Organization ID
    client_ip = Column(String(45), nullable=True, index=True)      # Client IP
    
    # Time aggregation
    time_bucket = Column(String(20), nullable=False, index=True)   # minute, hour, day
    time_period = Column(DateTime(timezone=True), nullable=False, index=True)  # Start of time period
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Indexes
    __table_args__ = (
        Index('idx_api_metrics_name_time', 'metric_name', 'time_period'),
        Index('idx_api_metrics_method_path', 'method', 'path'),
        Index('idx_api_metrics_status_code', 'status_code'),
        Index('idx_api_metrics_user_org', 'user_id', 'organization_id'),
    )


class APIPerformanceAlert(Base):
    """API Performance Alert model for storing performance alerts"""
    
    __tablename__ = "api_performance_alerts"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True)
    
    # Alert identification
    alert_id = Column(String(36), nullable=False, unique=True, index=True)  # UUID
    alert_type = Column(String(50), nullable=False, index=True)             # slow_request, error_rate, etc.
    severity = Column(String(20), nullable=False, index=True)               # low, medium, high, critical
    
    # Triggering conditions
    threshold_value = Column(Float, nullable=False)                         # Threshold that was exceeded
    actual_value = Column(Float, nullable=False)                            # Actual value that triggered alert
    metric_name = Column(String(100), nullable=False, index=True)           # Metric that triggered alert
    
    # Context
    method = Column(String(10), nullable=True, index=True)                  # HTTP method
    path = Column(String(500), nullable=True, index=True)                   # Request path
    user_id = Column(String(36), nullable=True, index=True)                 # User ID
    organization_id = Column(String(36), nullable=True, index=True)         # Organization ID
    
    # Alert status
    status = Column(String(20), nullable=False, default='active', index=True)  # active, resolved, acknowledged
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String(36), nullable=True)                         # User who resolved it
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Additional context
    description = Column(Text, nullable=True)                               # Alert description
    recommendations = Column(Text, nullable=True)                           # Recommendations for resolution
    
    # Indexes
    __table_args__ = (
        Index('idx_api_alerts_type_status', 'alert_type', 'status'),
        Index('idx_api_alerts_severity_created', 'severity', 'created_at'),
        Index('idx_api_alerts_user_org', 'user_id', 'organization_id'),
    ) 
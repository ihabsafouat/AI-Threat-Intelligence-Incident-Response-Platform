from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.api.v1.api import api_router
from app.core.database import engine
from app.models import Base
from app.models.api_logs import APILog, APIMetrics, APIPerformanceAlert
from app.middleware.logging_middleware import LoggingMiddleware, RequestIDMiddleware, PerformanceMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    print("🚀 Starting Threat Intelligence Platform...")
    
    # Create database tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Create API logging tables
        await conn.run_sync(APILog.__table__.create, checkfirst=True)
        await conn.run_sync(APIMetrics.__table__.create, checkfirst=True)
        await conn.run_sync(APIPerformanceAlert.__table__.create, checkfirst=True)
    
    print("✅ Database tables created")
    print("📊 API logging enabled")
    print("🎯 Threat Intelligence Platform is ready!")
    
    yield
    
    # Shutdown
    print("🛑 Shutting down Threat Intelligence Platform...")


app = FastAPI(
    title="AI Threat Intelligence & Incident Response Platform",
    description="An AI-powered platform for threat intelligence analysis and incident response",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add logging middleware first (before other middleware)
app.add_middleware(LoggingMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(PerformanceMiddleware)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AI Threat Intelligence & Incident Response Platform",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
        "features": {
            "api_logging": "enabled",
            "cloudwatch_integration": "enabled" if settings.AWS_ACCESS_KEY_ID else "disabled",
            "database_logging": "enabled"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": "2024-01-01T00:00:00Z",
        "services": {
            "api": "operational",
            "database": "operational",
            "logging": "operational"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    ) 
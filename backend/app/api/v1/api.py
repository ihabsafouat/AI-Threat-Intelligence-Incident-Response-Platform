from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    users,
    threats,
    vulnerabilities,
    assets,
    incidents,
    organizations,
    analytics,
    ml
)

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(threats.router, prefix="/threats", tags=["threats"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
api_router.include_router(assets.router, prefix="/assets", tags=["assets"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
api_router.include_router(organizations.router, prefix="/organizations", tags=["organizations"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])
api_router.include_router(ml.router, prefix="/ml", tags=["machine-learning"]) 
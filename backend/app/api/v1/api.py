from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    auth_external,
    users,
    threats,
    vulnerabilities,
    assets,
    incidents,
    organizations,
    analytics,
    ml,
    rbac
)

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(auth_external.router, tags=["external-authentication"])
api_router.include_router(users.router, prefix="/users", tags=["user-management"])
api_router.include_router(threats.router, prefix="/threats", tags=["threat-intelligence"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerability-management"])
api_router.include_router(assets.router, prefix="/assets", tags=["asset-management"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["incident-response"])
api_router.include_router(organizations.router, prefix="/organizations", tags=["organization-management"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])
api_router.include_router(ml.router, prefix="/ml", tags=["machine-learning"])
api_router.include_router(rbac.router, prefix="/rbac", tags=["rbac-management"]) 
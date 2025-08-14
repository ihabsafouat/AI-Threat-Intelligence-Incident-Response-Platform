"""
Threat Intelligence API Endpoints

Provides endpoints for threat management with RBAC integration.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.rbac import (
    get_db_session, get_current_user, require_permissions, require_roles
)
from app.models.threat import Threat
from app.schemas.threat import ThreatCreate, ThreatUpdate, ThreatResponse

router = APIRouter(prefix="/threats", tags=["threat-intelligence"])


@router.get("/", response_model=List[ThreatResponse])
@require_permissions(["threat:read"])
async def get_threats(
    skip: int = Query(0, ge=0, description="Number of threats to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of threats to return"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    status: Optional[str] = Query(None, description="Filter by threat status"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get a list of threats with filtering and pagination."""
    query = db.query(Threat)
    
    # Apply filters
    if threat_type:
        query = query.filter(Threat.threat_type == threat_type)
    if severity:
        query = query.filter(Threat.severity == severity)
    if status:
        query = query.filter(Threat.status == status)
    
    threats = query.offset(skip).limit(limit).all()
    return threats


@router.get("/{threat_id}", response_model=ThreatResponse)
@require_permissions(["threat:read"])
async def get_threat(
    threat_id: int,
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get a specific threat by ID."""
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found"
        )
    return threat


@router.post("/", response_model=ThreatResponse, status_code=status.HTTP_201_CREATED)
@require_permissions(["threat:create"])
async def create_threat(
    threat_data: ThreatCreate,
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Create a new threat."""
    threat = Threat(
        **threat_data.dict(),
        created_by=current_user.id
    )
    
    db.add(threat)
    db.commit()
    db.refresh(threat)
    return threat


@router.put("/{threat_id}", response_model=ThreatResponse)
@require_permissions(["threat:update"])
async def update_threat(
    threat_id: int,
    threat_data: ThreatUpdate,
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Update an existing threat."""
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found"
        )
    
    # Update threat fields
    update_data = threat_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        if hasattr(threat, field):
            setattr(threat, field, value)
    
    threat.updated_by = current_user.id
    db.commit()
    db.refresh(threat)
    return threat


@router.delete("/{threat_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permissions(["threat:delete"])
async def delete_threat(
    threat_id: int,
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Delete a threat."""
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found"
        )
    
    db.delete(threat)
    db.commit()


@router.post("/{threat_id}/analyze", response_model=ThreatResponse)
@require_permissions(["threat:analyze"])
async def analyze_threat(
    threat_id: int,
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Analyze a threat (requires threat:analyze permission)."""
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found"
        )
    
    # Update threat status to indicate analysis
    threat.status = "analyzing"
    threat.updated_by = current_user.id
    db.commit()
    db.refresh(threat)
    
    return threat


@router.post("/{threat_id}/export")
@require_permissions(["threat:export"])
async def export_threat(
    threat_id: int,
    format: str = Query("json", description="Export format (json, csv, pdf)"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Export a threat (requires threat:export permission)."""
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found"
        )
    
    # Mock export functionality
    return {
        "message": f"Threat {threat_id} exported in {format} format",
        "threat_id": threat_id,
        "format": format,
        "exported_by": current_user.id,
        "exported_at": "2024-01-01T00:00:00Z"
    }


@router.get("/search", response_model=List[ThreatResponse])
@require_permissions(["threat:read"])
async def search_threats(
    q: str = Query(..., description="Search query for threat name, description, or indicators"),
    skip: int = Query(0, ge=0, description="Number of threats to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of threats to return"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Search threats by name, description, or indicators."""
    query = db.query(Threat).filter(
        (
            Threat.name.ilike(f"%{q}%") |
            Threat.description.ilike(f"%{q}%") |
            Threat.indicators.ilike(f"%{q}%")
        )
    )
    
    threats = query.offset(skip).limit(limit).all()
    return threats


@router.get("/statistics/summary")
@require_permissions(["threat:read"])
async def get_threat_statistics(
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get threat statistics summary."""
    total_threats = db.query(Threat).count()
    active_threats = db.query(Threat).filter(Threat.status == "active").count()
    high_severity = db.query(Threat).filter(Threat.severity == "high").count()
    medium_severity = db.query(Threat).filter(Threat.severity == "medium").count()
    low_severity = db.query(Threat).filter(Threat.severity == "low").count()
    
    return {
        "total_threats": total_threats,
        "active_threats": active_threats,
        "severity_breakdown": {
            "high": high_severity,
            "medium": medium_severity,
            "low": low_severity
        }
    }


@router.post("/bulk-import")
@require_permissions(["threat:create"])
async def bulk_import_threats(
    threats_data: List[ThreatCreate],
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Bulk import threats (requires threat:create permission)."""
    imported_threats = []
    
    for threat_data in threats_data:
        threat = Threat(
            **threat_data.dict(),
            created_by=current_user.id
        )
        db.add(threat)
        imported_threats.append(threat)
    
    db.commit()
    
    # Refresh all imported threats
    for threat in imported_threats:
        db.refresh(threat)
    
    return {
        "message": f"Successfully imported {len(imported_threats)} threats",
        "imported_count": len(imported_threats),
        "imported_by": current_user.id
    }


@router.post("/{threat_id}/share")
@require_permissions(["threat:read"])
async def share_threat(
    threat_id: int,
    share_with: List[int] = Query(..., description="List of user IDs to share with"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Share a threat with other users."""
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found"
        )
    
    # Mock sharing functionality
    return {
        "message": f"Threat {threat_id} shared with {len(share_with)} users",
        "threat_id": threat_id,
        "shared_with": share_with,
        "shared_by": current_user.id
    } 
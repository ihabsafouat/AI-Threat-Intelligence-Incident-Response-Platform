"""
Incident Response API Endpoints

Provides endpoints for incident management with RBAC integration.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.rbac import (
    get_db_session, get_current_user, require_permissions, require_roles
)
from app.models.incident import Incident
from app.schemas.incident import IncidentCreate, IncidentUpdate, IncidentResponse

router = APIRouter(prefix="/incidents", tags=["incident-response"])


@router.get("/", response_model=List[IncidentResponse])
@require_permissions(["incident:read"])
async def get_incidents(
    skip: int = Query(0, ge=0, description="Number of incidents to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of incidents to return"),
    status: Optional[str] = Query(None, description="Filter by incident status"),
    priority: Optional[str] = Query(None, description="Filter by priority level"),
    assigned_to: Optional[int] = Query(None, description="Filter by assigned user ID"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get a list of incidents with filtering and pagination."""
    query = db.query(Incident)
    
    # Apply filters
    if status:
        query = query.filter(Incident.status == status)
    if priority:
        query = query.filter(Incident.priority == priority)
    if assigned_to:
        query = query.filter(Incident.assigned_to == assigned_to)
    
    # Users can only see incidents they're assigned to unless they have admin privileges
    if not current_user.is_superuser:
        query = query.filter(Incident.assigned_to == current_user.id)
    
    incidents = query.offset(skip).limit(limit).all()
    return incidents


@router.get("/{incident_id}", response_model=IncidentResponse)
@require_permissions(["incident:read"])
async def get_incident(
    incident_id: int,
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get a specific incident by ID."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Check if user has access to this incident
    if not current_user.is_superuser and incident.assigned_to != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this incident"
        )
    
    return incident


@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
@require_permissions(["incident:create"])
async def create_incident(
    incident_data: IncidentCreate,
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Create a new incident."""
    incident = Incident(
        **incident_data.dict(),
        created_by=current_user.id,
        assigned_to=incident_data.assigned_to or current_user.id
    )
    
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@router.put("/{incident_id}", response_model=IncidentResponse)
@require_permissions(["incident:update"])
async def update_incident(
    incident_id: int,
    incident_data: IncidentUpdate,
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Update an existing incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Check if user has access to update this incident
    if not current_user.is_superuser and incident.assigned_to != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to update this incident"
        )
    
    # Update incident fields
    update_data = incident_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        if hasattr(incident, field):
            setattr(incident, field, value)
    
    incident.updated_by = current_user.id
    db.commit()
    db.refresh(incident)
    return incident


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permissions(["incident:delete"])
async def delete_incident(
    incident_id: int,
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Delete an incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Only superusers or incident creators can delete incidents
    if not current_user.is_superuser and incident.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to delete this incident"
        )
    
    db.delete(incident)
    db.commit()


@router.post("/{incident_id}/assign")
@require_permissions(["incident:update"])
async def assign_incident(
    incident_id: int,
    user_id: int = Query(..., description="User ID to assign the incident to"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Assign an incident to a user."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Check if user has access to update this incident
    if not current_user.is_superuser and incident.assigned_to != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to update this incident"
        )
    
    # Update assignment
    incident.assigned_to = user_id
    incident.updated_by = current_user.id
    db.commit()
    db.refresh(incident)
    
    return {
        "message": f"Incident {incident_id} assigned to user {user_id}",
        "incident_id": incident_id,
        "assigned_to": user_id,
        "assigned_by": current_user.id
    }


@router.post("/{incident_id}/escalate")
@require_permissions(["incident:update"])
async def escalate_incident(
    incident_id: int,
    priority: str = Query(..., description="New priority level"),
    reason: str = Query(..., description="Reason for escalation"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Escalate an incident priority."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Check if user has access to update this incident
    if not current_user.is_superuser and incident.assigned_to != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to update this incident"
        )
    
    # Update priority
    incident.priority = priority
    incident.updated_by = current_user.id
    db.commit()
    db.refresh(incident)
    
    return {
        "message": f"Incident {incident_id} escalated to {priority} priority",
        "incident_id": incident_id,
        "new_priority": priority,
        "escalated_by": current_user.id,
        "reason": reason
    }


@router.post("/{incident_id}/close")
@require_permissions(["incident:update"])
async def close_incident(
    incident_id: int,
    resolution: str = Query(..., description="Resolution summary"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Close an incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Check if user has access to update this incident
    if not current_user.is_superuser and incident.assigned_to != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to update this incident"
        )
    
    # Close incident
    incident.status = "closed"
    incident.resolution = resolution
    incident.closed_at = "2024-01-01T00:00:00Z"  # Mock timestamp
    incident.updated_by = current_user.id
    db.commit()
    db.refresh(incident)
    
    return {
        "message": f"Incident {incident_id} closed",
        "incident_id": incident_id,
        "closed_by": current_user.id,
        "resolution": resolution
    }


@router.get("/search", response_model=List[IncidentResponse])
@require_permissions(["incident:read"])
async def search_incidents(
    q: str = Query(..., description="Search query for incident title, description, or tags"),
    skip: int = Query(0, ge=0, description="Number of incidents to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of incidents to return"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Search incidents by title, description, or tags."""
    query = db.query(Incident).filter(
        (
            Incident.title.ilike(f"%{q}%") |
            Incident.description.ilike(f"%{q}%") |
            Incident.tags.ilike(f"%{q}%")
        )
    )
    
    # Users can only see incidents they're assigned to unless they have admin privileges
    if not current_user.is_superuser:
        query = query.filter(Incident.assigned_to == current_user.id)
    
    incidents = query.offset(skip).limit(limit).all()
    return incidents


@router.get("/statistics/summary")
@require_permissions(["incident:read"])
async def get_incident_statistics(
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get incident statistics summary."""
    query = db.query(Incident)
    
    # Users can only see statistics for incidents they're assigned to unless they have admin privileges
    if not current_user.is_superuser:
        query = query.filter(Incident.assigned_to == current_user.id)
    
    total_incidents = query.count()
    open_incidents = query.filter(Incident.status == "open").count()
    closed_incidents = query.filter(Incident.status == "closed").count()
    high_priority = query.filter(Incident.priority == "high").count()
    medium_priority = query.filter(Incident.priority == "medium").count()
    low_priority = query.filter(Incident.priority == "low").count()
    
    return {
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "closed_incidents": closed_incidents,
        "priority_breakdown": {
            "high": high_priority,
            "medium": medium_priority,
            "low": low_priority
        }
    }


@router.post("/bulk-close")
@require_permissions(["incident:update"])
async def bulk_close_incidents(
    incident_ids: List[int] = Query(..., description="List of incident IDs to close"),
    resolution: str = Query(..., description="Resolution summary for all incidents"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Bulk close multiple incidents."""
    closed_count = 0
    
    for incident_id in incident_ids:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident:
            # Check if user has access to update this incident
            if current_user.is_superuser or incident.assigned_to == current_user.id:
                incident.status = "closed"
                incident.resolution = resolution
                incident.closed_at = "2024-01-01T00:00:00Z"  # Mock timestamp
                incident.updated_by = current_user.id
                closed_count += 1
    
    db.commit()
    
    return {
        "message": f"Successfully closed {closed_count} incidents",
        "closed_count": closed_count,
        "total_requested": len(incident_ids),
        "closed_by": current_user.id,
        "resolution": resolution
    }


@router.get("/my-incidents", response_model=List[IncidentResponse])
@require_permissions(["incident:read"])
async def get_my_incidents(
    skip: int = Query(0, ge=0, description="Number of incidents to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of incidents to return"),
    db: Session = Depends(get_db_session),
    current_user = Depends(get_current_user)
):
    """Get incidents assigned to the current user."""
    incidents = db.query(Incident).filter(
        Incident.assigned_to == current_user.id
    ).offset(skip).limit(limit).all()
    
    return incidents 
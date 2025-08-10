from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Incident(Base):
    """Security incidents"""
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    assigned_to_id = Column(Integer, ForeignKey("users.id"))
    
    # Incident identification
    incident_id = Column(String(50), unique=True, index=True)  # INC-2023-001
    title = Column(String(500), nullable=False)
    description = Column(Text)
    
    # Classification
    incident_type = Column(String(100))  # malware, phishing, data_breach, etc.
    severity = Column(String(20))  # low, medium, high, critical
    priority = Column(String(20))  # low, medium, high, critical
    status = Column(String(50), default="open")  # open, in_progress, resolved, closed
    
    # Threat information
    threat_actor = Column(String(255))
    attack_vector = Column(String(100))
    ioc_type = Column(String(50))
    ioc_value = Column(String(500))
    
    # Affected assets
    affected_assets = Column(JSON)  # List of affected asset IDs
    business_impact = Column(String(20))  # low, medium, high, critical
    financial_impact = Column(Float)
    
    # Timeline
    detection_time = Column(DateTime(timezone=True))
    containment_time = Column(DateTime(timezone=True))
    eradication_time = Column(DateTime(timezone=True))
    recovery_time = Column(DateTime(timezone=True))
    
    # Response
    response_team = Column(JSON)  # List of team members
    external_partners = Column(JSON)  # Law enforcement, vendors, etc.
    
    # Documentation
    evidence_collected = Column(JSON)
    lessons_learned = Column(Text)
    recommendations = Column(Text)
    
    # Metadata
    tags = Column(JSON)
    custom_fields = Column(JSON)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    closed_at = Column(DateTime(timezone=True))
    
    # Relationships
    organization = relationship("Organization", back_populates="incidents")
    assigned_to = relationship("User", back_populates="incidents")
    responses = relationship("IncidentResponse", back_populates="incident")
    
    def __repr__(self):
        return f"<Incident(id={self.id}, incident_id='{self.incident_id}', title='{self.title}')>"


class IncidentResponse(Base):
    """Individual response actions for incidents"""
    __tablename__ = "incidents_responses"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    responder_id = Column(Integer, ForeignKey("users.id"))
    
    # Response details
    action_type = Column(String(100))  # containment, eradication, recovery, communication
    action_title = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Execution
    status = Column(String(50), default="planned")  # planned, in_progress, completed, failed
    priority = Column(String(20))  # low, medium, high, critical
    
    # Timeline
    planned_start = Column(DateTime(timezone=True))
    actual_start = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    estimated_duration = Column(Integer)  # minutes
    actual_duration = Column(Integer)  # minutes
    
    # Resources
    resources_required = Column(JSON)
    tools_used = Column(JSON)
    team_members = Column(JSON)
    
    # Results
    outcome = Column(String(50))  # successful, partial, failed
    results = Column(Text)
    artifacts = Column(JSON)  # Files, logs, evidence
    
    # Notes
    notes = Column(Text)
    lessons_learned = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    incident = relationship("Incident", back_populates="responses")
    responder = relationship("User", back_populates="responses")
    
    def __repr__(self):
        return f"<IncidentResponse(id={self.id}, action_type='{self.action_type}', title='{self.action_title}')>" 
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Organization(Base):
    """Organizations for multi-tenant support"""
    __tablename__ = "organizations"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Organization details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    domain = Column(String(255))
    
    # Contact information
    contact_email = Column(String(255))
    contact_phone = Column(String(20))
    address = Column(Text)
    country = Column(String(100))
    
    # Industry and size
    industry = Column(String(100))
    size = Column(String(50))  # small, medium, large, enterprise
    employee_count = Column(Integer)
    
    # Security profile
    security_maturity = Column(String(50))  # basic, intermediate, advanced
    compliance_frameworks = Column(JSON)  # ISO 27001, SOC 2, GDPR, etc.
    security_team_size = Column(Integer)
    
    # Subscription and licensing
    subscription_plan = Column(String(50), default="basic")  # basic, professional, enterprise
    max_users = Column(Integer, default=10)
    max_assets = Column(Integer, default=100)
    features_enabled = Column(JSON)
    
    # Configuration
    timezone = Column(String(50), default="UTC")
    language = Column(String(10), default="en")
    date_format = Column(String(20), default="YYYY-MM-DD")
    
    # Security settings
    password_policy = Column(JSON)
    mfa_required = Column(Boolean, default=False)
    session_timeout = Column(Integer, default=30)  # minutes
    ip_whitelist = Column(JSON)
    
    # Integration settings
    integrations = Column(JSON)  # SIEM, ticketing, etc.
    api_keys = Column(JSON)
    webhooks = Column(JSON)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_trial = Column(Boolean, default=True)
    trial_expires_at = Column(DateTime(timezone=True))
    
    # Metadata
    tags = Column(JSON)
    custom_fields = Column(JSON)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    users = relationship("User", back_populates="organization")
    assets = relationship("Asset", back_populates="organization")
    incidents = relationship("Incident", back_populates="organization")
    
    def __repr__(self):
        return f"<Organization(id={self.id}, name='{self.name}', domain='{self.domain}')>" 
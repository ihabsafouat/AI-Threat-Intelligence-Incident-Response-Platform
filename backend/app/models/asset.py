from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class Asset(Base):
    """Organizational assets (servers, applications, networks, etc.)"""
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    
    # Asset identification
    name = Column(String(255), nullable=False)
    asset_type = Column(String(100))  # server, application, network, database, etc.
    asset_subtype = Column(String(100))  # web_server, database_server, etc.
    
    # Technical details
    ip_address = Column(String(45))  # IPv4 or IPv6
    hostname = Column(String(255))
    domain = Column(String(255))
    mac_address = Column(String(17))
    
    # Software and versions
    operating_system = Column(String(255))
    os_version = Column(String(100))
    software_installed = Column(JSON)  # List of installed software
    
    # Network information
    network_segment = Column(String(100))
    vlan = Column(String(50))
    subnet = Column(String(50))
    
    # Business context
    business_unit = Column(String(255))
    department = Column(String(255))
    owner = Column(String(255))
    criticality = Column(String(20))  # low, medium, high, critical
    
    # Security posture
    risk_score = Column(Float, default=0.0)
    security_status = Column(String(50), default="unknown")  # secure, at_risk, compromised
    last_scan = Column(DateTime(timezone=True))
    next_scan = Column(DateTime(timezone=True))
    
    # Location and physical details
    location = Column(String(255))
    data_center = Column(String(255))
    rack_position = Column(String(100))
    
    # Status and lifecycle
    status = Column(String(50), default="active")  # active, inactive, decommissioned
    lifecycle_stage = Column(String(50))  # development, staging, production
    
    # Metadata
    tags = Column(JSON)
    custom_fields = Column(JSON)
    notes = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_updated = Column(DateTime(timezone=True))
    
    # Relationships
    organization = relationship("Organization", back_populates="assets")
    vulnerabilities = relationship("Vulnerability", back_populates="asset")
    
    def __repr__(self):
        return f"<Asset(id={self.id}, name='{self.name}', type='{self.asset_type}')>"


class AssetVulnerability(Base):
    """Many-to-many relationship between assets and vulnerabilities with additional metadata"""
    __tablename__ = "asset_vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    
    # Relationship specific data
    detection_date = Column(DateTime(timezone=True))
    remediation_status = Column(String(50), default="pending")  # pending, in_progress, completed
    remediation_notes = Column(Text)
    
    # Risk assessment for this specific asset
    asset_specific_risk = Column(Float)
    business_impact = Column(String(20))  # low, medium, high, critical
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    def __repr__(self):
        return f"<AssetVulnerability(asset_id={self.asset_id}, vulnerability_id={self.vulnerability_id})>" 
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class ThreatFeed(Base):
    """Threat intelligence feed sources"""
    __tablename__ = "threat_feeds"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    url = Column(String(500), nullable=False)
    feed_type = Column(String(50))  # cve, ioc, malware, etc.
    format = Column(String(50))  # json, csv, stix, etc.
    is_active = Column(Boolean, default=True)
    last_fetch = Column(DateTime(timezone=True))
    fetch_interval = Column(Integer, default=3600)  # seconds
    
    # Authentication
    api_key = Column(String(255))
    username = Column(String(255))
    password = Column(String(255))
    
    # Configuration
    config = Column(JSON)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    threats = relationship("Threat", back_populates="feed")
    
    def __repr__(self):
        return f"<ThreatFeed(id={self.id}, name='{self.name}', type='{self.feed_type}')>"


class Threat(Base):
    """Threat intelligence data"""
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, index=True)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id"))
    
    # Threat information
    title = Column(String(500), nullable=False)
    description = Column(Text)
    threat_type = Column(String(100))  # malware, phishing, apt, etc.
    severity = Column(String(20))  # low, medium, high, critical
    confidence = Column(Float)  # 0.0 to 1.0
    
    # Threat actor information
    actor_name = Column(String(255))
    actor_type = Column(String(100))  # nation-state, cybercriminal, etc.
    motivation = Column(String(100))
    
    # Technical details
    ioc_type = Column(String(50))  # ip, domain, hash, url, etc.
    ioc_value = Column(String(500))
    malware_family = Column(String(255))
    attack_vector = Column(String(100))
    
    # Metadata
    tags = Column(JSON)
    references = Column(JSON)
    raw_data = Column(JSON)
    
    # Timestamps
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    feed = relationship("ThreatFeed", back_populates="threats")
    indicators = relationship("ThreatIndicator", back_populates="threat")
    
    def __repr__(self):
        return f"<Threat(id={self.id}, title='{self.title}', type='{self.threat_type}')>"


class ThreatIndicator(Base):
    """Individual threat indicators (IOCs)"""
    __tablename__ = "threat_indicators"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"))
    
    # Indicator details
    indicator_type = Column(String(50), nullable=False)  # ip, domain, hash, url, email
    indicator_value = Column(String(500), nullable=False)
    indicator_format = Column(String(50))  # md5, sha256, ipv4, etc.
    
    # Analysis
    confidence = Column(Float, default=0.5)
    threat_score = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
    
    # Metadata
    tags = Column(JSON)
    context = Column(JSON)
    
    # Timestamps
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    threat = relationship("Threat", back_populates="indicators")
    
    def __repr__(self):
        return f"<ThreatIndicator(id={self.id}, type='{self.indicator_type}', value='{self.indicator_value}')>" 
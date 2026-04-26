from sqlalchemy import Column, Integer, String, Float, ForeignKey, Text, DateTime, Table, Enum, Boolean, Date, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

# Association table for many-to-many Host <-> Vulnerability
host_vulnerability = Table(
    "host_vulnerability",
    Base.metadata,
    Column("host_id", Integer, ForeignKey("hosts.id"), primary_key=True, index=True),
    Column("vulnerability_id", Integer, ForeignKey("vulnerabilities.pluginid"), primary_key=True, index=True),
    Column("vuln_status", String(20), nullable=False, default="active", index=True),
    Column("plugin_output", Text, nullable=True),
    Column("closed_date", DateTime, nullable=True)
)

class Host(Base):
    __tablename__ = "hosts"
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), unique=False, index=True)
    host_ip = Column(String(255), unique=False, index=True)
    last_scan_date = Column(DateTime)
    status = Column(String(50))
    server_owner = Column(String(255), nullable=True)
    application_dependent = Column(String(255), nullable=True)
    os_name = Column(String(50), nullable=True, default="Unknown")  # OS type: Windows, Linux, or Unknown
    ready_for_rescan = Column(Boolean, default=False, nullable=False)  # Toggle for immediate rescan
    vulnerabilities = relationship(
        "Vulnerability",
        secondary=host_vulnerability,
        back_populates="hosts"
    )

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, nullable=True)
    pluginid = Column(Integer, primary_key=True)
    pluginfamily = Column(String(255), nullable=True)
    pluginname = Column(String(255), nullable=True, index=True)
    severity = Column(Integer, nullable=True, index=True)
    synopsis = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    cvss_base_score = Column(Float, nullable=True)
    solution = Column(Text, nullable=True)
    cpe = Column(String(255), nullable=True, index=True)
    month_of_discovery = Column(String(7))  # Format: 'YYYY-MM'
    # plugin_output moved to host_vulnerability association to be per-host
    hosts = relationship(
        "Host",
        secondary=host_vulnerability,
        back_populates="vulnerabilities"
    )
    # Only essential fields retained for new API data

class VulnerabilityException(Base):
    __tablename__ = "vulnerability_exceptions"
    
    id = Column(Integer, primary_key=True, index=True)
    exception_id = Column(String(50), unique=True, nullable=False, index=True)  # User-defined exception ID
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.pluginid"), nullable=True)  # Null for host-specific exceptions
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)  # Null for vulnerability-specific exceptions
    exception_type = Column(Enum("vulnerability", "host", "vulnerability_host", name="exception_type_enum"), nullable=False)
    reason = Column(Text, nullable=False)  # Reason for the exception
    expiry_date = Column(Date, nullable=False, index=True)  # When the exception expires
    created_by = Column(String(255), nullable=False)  # User who created the exception
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)  # Whether exception is currently active
    
    # Add composite indexes for common query patterns
    __table_args__ = (
        Index('idx_vuln_exception_lookup', 'vulnerability_id', 'exception_type', 'is_active', 'expiry_date'),
        Index('idx_host_exception_lookup', 'host_id', 'exception_type', 'is_active', 'expiry_date'),
        Index('idx_vuln_host_exception_lookup', 'vulnerability_id', 'host_id', 'exception_type', 'is_active', 'expiry_date'),
    )
    
    # Relationships
    vulnerability = relationship("Vulnerability", backref="exceptions")
    host = relationship("Host", backref="exceptions")
    
    def __repr__(self):
        return f"<VulnerabilityException(id={self.exception_id}, type={self.exception_type}, expires={self.expiry_date})>"
    
    @property
    def is_expired(self):
        """Check if the exception has expired"""
        return datetime.now().date() > self.expiry_date
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "exception_id": self.exception_id,
            "vulnerability_id": self.vulnerability_id,
            "host_id": self.host_id,
            "exception_type": self.exception_type,
            "reason": self.reason,
            "expiry_date": self.expiry_date.isoformat() if self.expiry_date else None,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "is_active": self.is_active,
            "is_expired": self.is_expired
        }
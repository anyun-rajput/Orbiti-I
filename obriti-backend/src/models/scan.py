from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class ScanDetails(BaseModel):
    id: int
    name: str
    status: str
    start_time: str
    end_time: str
    hosts: List[dict]
    vulnerabilities: Optional[List[dict]] = None

class BatchScan(Base):
    __tablename__ = "batch_scans"
    id = Column(Integer, primary_key=True, index=True)
    batch_name = Column(String(255), nullable=False)
    batch_size = Column(Integer, nullable=False)
    batch_job = Column(String(50), nullable=False)  # 'vuln scan' or 'compliance scan'
    job_start_time = Column(String(20), nullable=False)  # e.g., '14:00'
    job_end_time = Column(String(20), nullable=False)    # e.g., '16:00'
    week_day = Column(String(20), nullable=False)        # e.g., 'Monday' or '0-6'
    created_at = Column(DateTime, default=datetime.utcnow)

# Role model for user management
class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)  # 'admin' or 'org_team'
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    users = relationship("User", back_populates="role")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)  # Made nullable for SSO users
    first_name = Column(String(50), nullable=True)
    last_name = Column(String(50), nullable=True)
    email = Column(String(100), unique=True, index=True, nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    auth_provider = Column(String(50), default="local")  # 'local' or 'microsoft'
    external_id = Column(String(255), nullable=True)  # Microsoft user ID for SSO users
    
    role = relationship("Role", back_populates="users")


class IntegrationConfig(Base):
    __tablename__ = "integration_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    integration_type = Column(String(50), nullable=False)  # 'microsoft_sso' or 'nessus'
    enabled = Column(Boolean, default=False)
    config_data = Column(Text, nullable=True)  # JSON string containing configuration
    status = Column(String(50), default="not_configured")  # 'configured', 'not_configured', 'error', 'connected', 'disconnected'
    last_tested = Column(DateTime, nullable=True)
    last_sync = Column(DateTime, nullable=True)
    extra_metadata = Column(Text, nullable=True)  # Additional metadata like vulnerability count, etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    creator = relationship("User")
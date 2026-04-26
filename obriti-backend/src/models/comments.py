from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from models.vuln import Base

class CommentType(enum.Enum):
    VULNERABILITY = "vulnerability"  # Comment applies to vulnerability across all hosts
    HOST = "host"                   # Comment applies to host across all vulnerabilities
    HOST_VULNERABILITY = "host_vulnerability"  # Comment applies to specific vuln on specific host

class Comment(Base):
    __tablename__ = "comments"
    
    id = Column(Integer, primary_key=True, index=True)
    comment_type = Column(String(50), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(255), nullable=False)  # Username who created the comment
    
    # Foreign keys - only one will be populated based on comment_type
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.pluginid"), nullable=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    
    # For host_vulnerability comments, both host_id and vulnerability_id will be populated
    
    # Relationships
    vulnerability = relationship("Vulnerability", foreign_keys=[vulnerability_id])
    host = relationship("Host", foreign_keys=[host_id])
    
    def __repr__(self):
        return f"<Comment(id={self.id}, type={self.comment_type}, content='{self.content[:50]}...')>"

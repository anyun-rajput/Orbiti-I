from sqlalchemy import Column, Integer, String, Date, DateTime, Index
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, date

Base = declarative_base()

class DailyVulnerabilitySummary(Base):
    """
    Daily summary table for vulnerability counts by severity.
    This table stores pre-calculated daily counts for efficient trend analysis.
    Counts represent total active vulnerabilities at end of day, not just discovered that day.
    """
    __tablename__ = "daily_vulnerability_summary"
    
    id = Column(Integer, primary_key=True, index=True)
    summary_date = Column(Date, nullable=False, index=True)  # Date for this summary
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    total_count = Column(Integer, default=0, nullable=False)  # Sum of all severities
    total_hosts_scanned = Column(Integer, default=0, nullable=False)  # Number of hosts scanned on this date
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Create unique index on summary_date to prevent duplicates
    __table_args__ = (
        Index('idx_summary_date_unique', 'summary_date', unique=True),
        Index('idx_summary_date_range', 'summary_date'),
    )
    
    def __repr__(self):
        return f"<DailyVulnerabilitySummary(date={self.summary_date}, critical={self.critical_count}, high={self.high_count}, medium={self.medium_count}, low={self.low_count})>"
    
    @property
    def total_vulnerabilities(self):
        """Calculate total vulnerabilities for this day"""
        return self.critical_count + self.high_count + self.medium_count + self.low_count
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "date": self.summary_date.isoformat(),
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "total": self.total_vulnerabilities,
            "total_hosts_scanned": self.total_hosts_scanned,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }

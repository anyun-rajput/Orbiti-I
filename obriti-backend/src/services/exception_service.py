"""
Service layer for handling vulnerability exception logic and filtering
"""

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, text
from models.vuln import VulnerabilityException, Vulnerability, Host, host_vulnerability
from datetime import date, datetime, timedelta
from typing import List, Dict, Optional, Tuple

class ExceptionService:
    """Service class for vulnerability exception operations"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def get_active_exceptions(self) -> List[VulnerabilityException]:
        """Get all active, non-expired exceptions"""
        current_date = date.today()
        return self.session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date
            )
        ).all()
    
    def get_exception_for_vulnerability_host(self, vulnerability_id: int, host_id: int) -> Optional[VulnerabilityException]:
        """Get exception for specific vulnerability-host combination"""
        current_date = date.today()
        
        # Check for specific vulnerability-host exception first
        exception = self.session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.vulnerability_id == vulnerability_id,
                VulnerabilityException.host_id == host_id,
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date
            )
        ).first()
        
        if exception:
            return exception
        
        # Check for vulnerability-only exception
        exception = self.session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.vulnerability_id == vulnerability_id,
                VulnerabilityException.host_id.is_(None),
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date
            )
        ).first()
        
        if exception:
            return exception
        
        # Check for host-only exception
        exception = self.session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.host_id == host_id,
                VulnerabilityException.vulnerability_id.is_(None),
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date
            )
        ).first()
        
        return exception
    
    def get_vulnerabilities_with_exceptions_excluded(self, page: int = 1, page_size: int = 20, 
                                                   search: str = "", severity: str = "all") -> Tuple[List[Dict], int]:
        """Get vulnerabilities excluding those with active exceptions"""
        current_date = date.today()
        
        # Build base query for vulnerabilities
        base_query = self.session.query(
            Vulnerability.pluginid.label("id"),
            Vulnerability.pluginname.label("name"),
            Vulnerability.severity,
            Vulnerability.description,
            Vulnerability.solution,
            Vulnerability.cpe.label("cve"),
            func.max(host_vulnerability.c.plugin_output).label("plugin_output"),
            func.count(host_vulnerability.c.host_id).label("host_count")
        ).join(
            host_vulnerability, Vulnerability.pluginid == host_vulnerability.c.vulnerability_id
        ).filter(
            Vulnerability.severity >= 1,
            host_vulnerability.c.vuln_status == 'active'
        )
        
        # Apply severity filter
        severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        reverse_severity_map = {v: k for k, v in severity_map.items()}
        
        if severity != "all" and severity in reverse_severity_map:
            base_query = base_query.filter(Vulnerability.severity == reverse_severity_map[severity])
        
        # Apply search filter
        if search:
            search_term = f"%{search.lower()}%"
            base_query = base_query.filter(
                or_(
                    Vulnerability.pluginname.ilike(search_term),
                    Vulnerability.cpe.ilike(search_term),
                    Vulnerability.description.ilike(search_term)
                )
            )
        
        # Group by vulnerability
        base_query = base_query.group_by(
            Vulnerability.pluginid, Vulnerability.pluginname, Vulnerability.severity,
            Vulnerability.description, Vulnerability.solution, Vulnerability.cpe
        )
        
        # Get total count before applying exception filter
        total_count = base_query.count()
        
        # Get vulnerability IDs that have active exceptions
        exception_vuln_ids = self.session.query(VulnerabilityException.vulnerability_id).filter(
            and_(
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date,
                VulnerabilityException.vulnerability_id.isnot(None)
            )
        ).subquery()
        
        # Exclude vulnerabilities with exceptions
        filtered_query = base_query.filter(
            ~Vulnerability.pluginid.in_(
                self.session.query(exception_vuln_ids.c.vulnerability_id)
            )
        )
        
        # Apply pagination
        vulnerabilities = filtered_query.order_by(
            Vulnerability.severity.desc(), 
            func.count(host_vulnerability.c.host_id).desc()
        ).offset((page - 1) * page_size).limit(page_size).all()
        
        # Convert to dictionary format
        result = []
        for vuln in vulnerabilities:
            result.append({
                "id": str(vuln.id),
                "name": vuln.name,
                "severity": severity_map.get(vuln.severity, "unknown"),
                "description": vuln.description,
                "solution": vuln.solution,
                "cve": vuln.cve,
                "plugin_output": vuln.plugin_output,
                "host_count": vuln.host_count
            })
        
        return result, total_count
    
    def get_vulnerability_counts_with_exceptions_excluded(self) -> Dict[str, int]:
        """Get vulnerability counts by severity excluding exceptions"""
        current_date = date.today()
        
        # Get vulnerability IDs that have active exceptions
        exception_vuln_ids = self.session.query(VulnerabilityException.vulnerability_id).filter(
            and_(
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date,
                VulnerabilityException.vulnerability_id.isnot(None)
            )
        ).subquery()
        
        # Count vulnerabilities by severity, excluding those with exceptions
        counts_query = self.session.query(
            Vulnerability.severity,
            func.count(Vulnerability.pluginid).label("count")
        ).filter(
            Vulnerability.severity >= 1,
            ~Vulnerability.pluginid.in_(
                self.session.query(exception_vuln_ids.c.vulnerability_id)
            ),
            Vulnerability.pluginid.in_(
                self.session.query(host_vulnerability.c.vulnerability_id).filter(
                    host_vulnerability.c.vuln_status == 'active'
                )
            )
        ).group_by(Vulnerability.severity)
        
        results = counts_query.all()
        
        # Map severity numbers to names
        severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        counts = {severity_map.get(sev, "unknown"): count for sev, count in results}
        
        # Ensure all severities are present
        for severity in ["critical", "high", "medium", "low"]:
            if severity not in counts:
                counts[severity] = 0
        
        return counts
    
    def get_host_vulnerabilities_with_exceptions_excluded(self, host_id: int) -> List[Dict]:
        """Get vulnerabilities for a specific host excluding those with active exceptions"""
        current_date = date.today()
        
        # Get exceptions for this host
        host_exceptions = self.session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.host_id == host_id,
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date
            )
        ).all()
        
        # Get vulnerability IDs to exclude
        excluded_vuln_ids = set()
        for exception in host_exceptions:
            if exception.vulnerability_id:
                excluded_vuln_ids.add(exception.vulnerability_id)
        
        # Query vulnerabilities for this host, excluding exceptions
        query = self.session.query(
            Vulnerability.pluginid,
            Vulnerability.pluginname,
            Vulnerability.severity,
            Vulnerability.description,
            Vulnerability.solution,
            Vulnerability.cpe,
            host_vulnerability.c.plugin_output,
            host_vulnerability.c.vuln_status
        ).join(
            host_vulnerability, Vulnerability.pluginid == host_vulnerability.c.vulnerability_id
        ).filter(
            host_vulnerability.c.host_id == host_id,
            host_vulnerability.c.vuln_status == 'active',
            ~Vulnerability.pluginid.in_(excluded_vuln_ids) if excluded_vuln_ids else True
        )
        
        results = query.all()
        
        # Convert to dictionary format
        severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        vulnerabilities = []
        for vuln in results:
            vulnerabilities.append({
                "id": str(vuln.pluginid),
                "name": vuln.pluginname,
                "severity": severity_map.get(vuln.severity, "unknown"),
                "description": vuln.description,
                "solution": vuln.solution,
                "cve": vuln.cpe,
                "plugin_output": vuln.plugin_output,
                "status": vuln.vuln_status
            })
        
        return vulnerabilities
    
    def get_exception_statistics(self) -> Dict[str, int]:
        """Get statistics about exceptions"""
        current_date = date.today()
        
        # Total active exceptions
        total_active = self.session.query(VulnerabilityException).filter(
            VulnerabilityException.is_active == True
        ).count()
        
        # Expired exceptions
        expired = self.session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date < current_date
            )
        ).count()
        
        # Exceptions expiring soon (within 7 days)
        expiring_soon = self.session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date,
                VulnerabilityException.expiry_date <= current_date + timedelta(days=7)
            )
        ).count()
        
        # Count by type
        by_type = self.session.query(
            VulnerabilityException.exception_type,
            func.count(VulnerabilityException.id)
        ).filter(
            VulnerabilityException.is_active == True
        ).group_by(VulnerabilityException.exception_type).all()
        
        type_counts = {row[0]: row[1] for row in by_type}
        
        return {
            "total_active": total_active,
            "expired": expired,
            "expiring_soon": expiring_soon,
            "by_type": type_counts
        }
    
    def cleanup_expired_exceptions(self) -> int:
        """Mark expired exceptions as inactive and return count of cleaned up exceptions"""
        current_date = date.today()
        
        expired_exceptions = self.session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date < current_date
            )
        ).all()
        
        count = 0
        for exception in expired_exceptions:
            exception.is_active = False
            count += 1
        
        self.session.commit()
        return count

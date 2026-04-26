"""
Utility functions for handling vulnerability exceptions
"""
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, text
from models.vuln import VulnerabilityException
from datetime import date


def get_exception_filter_conditions():
    """
    Returns SQLAlchemy filter conditions to exclude vulnerabilities that have active exceptions.
    This can be used in vulnerability queries to hide exceptions.
    
    Returns:
        list: List of filter conditions to exclude active exceptions
    """
    current_date = date.today()
    
    return [
        # Exclude vulnerabilities with active exceptions
        ~VulnerabilityException.query.filter(
            and_(
                VulnerabilityException.vulnerability_id == VulnerabilityException.vulnerability_id,
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date
            )
        ).exists()
    ]


def get_exception_filter_sql():
    """
    Returns raw SQL condition to exclude vulnerabilities that have active exceptions.
    This can be used in raw SQL queries.
    
    Returns:
        str: SQL condition to exclude active exceptions
    """
    return """
        AND NOT EXISTS (
            SELECT 1 FROM vulnerability_exceptions ve
            WHERE ve.vulnerability_id = v.pluginid
            AND ve.is_active = true
            AND ve.expiry_date >= CURRENT_DATE
        )
    """


def get_exception_filter_sql_with_host():
    """
    Returns raw SQL condition to exclude vulnerabilities that have active exceptions,
    including host-specific exceptions.
    
    Returns:
        str: SQL condition to exclude active exceptions (including host-specific)
    """
    return """
        AND NOT EXISTS (
            SELECT 1 FROM vulnerability_exceptions ve
            WHERE (
                (ve.vulnerability_id = v.pluginid AND ve.exception_type IN ('vulnerability', 'vulnerability_host'))
                OR (ve.host_id = h.id AND ve.exception_type IN ('host', 'vulnerability_host'))
            )
            AND ve.is_active = true
            AND ve.expiry_date >= CURRENT_DATE
        )
    """


def is_vulnerability_excepted(session: Session, vulnerability_id: int, host_id: int = None):
    """
    Check if a specific vulnerability (and optionally host) has an active exception.
    
    Args:
        session: Database session
        vulnerability_id: Vulnerability plugin ID
        host_id: Optional host ID for host-specific checks
        
    Returns:
        bool: True if the vulnerability has an active exception
    """
    current_date = date.today()
    
    query = session.query(VulnerabilityException).filter(
        and_(
            VulnerabilityException.is_active == True,
            VulnerabilityException.expiry_date >= current_date
        )
    )
    
    if host_id:
        # Check for vulnerability-specific, host-specific, or vulnerability-host exceptions
        query = query.filter(
            or_(
                and_(
                    VulnerabilityException.vulnerability_id == vulnerability_id,
                    VulnerabilityException.exception_type.in_(['vulnerability', 'vulnerability_host'])
                ),
                and_(
                    VulnerabilityException.host_id == host_id,
                    VulnerabilityException.exception_type.in_(['host', 'vulnerability_host'])
                ),
                and_(
                    VulnerabilityException.vulnerability_id == vulnerability_id,
                    VulnerabilityException.host_id == host_id,
                    VulnerabilityException.exception_type == 'vulnerability_host'
                )
            )
        )
    else:
        # Check only for vulnerability-specific exceptions
        query = query.filter(
            and_(
                VulnerabilityException.vulnerability_id == vulnerability_id,
                VulnerabilityException.exception_type == 'vulnerability'
            )
        )
    
    return query.first() is not None


def get_exception_info(session: Session, vulnerability_id: int, host_id: int = None):
    """
    Get information about active exceptions for a vulnerability.
    
    Args:
        session: Database session
        vulnerability_id: Vulnerability plugin ID
        host_id: Optional host ID for host-specific checks
        
    Returns:
        dict: Exception information or None if no active exception
    """
    current_date = date.today()
    
    query = session.query(VulnerabilityException).filter(
        and_(
            VulnerabilityException.is_active == True,
            VulnerabilityException.expiry_date >= current_date
        )
    )
    
    if host_id:
        # Check for any type of exception
        query = query.filter(
            or_(
                and_(
                    VulnerabilityException.vulnerability_id == vulnerability_id,
                    VulnerabilityException.exception_type.in_(['vulnerability', 'vulnerability_host'])
                ),
                and_(
                    VulnerabilityException.host_id == host_id,
                    VulnerabilityException.exception_type.in_(['host', 'vulnerability_host'])
                ),
                and_(
                    VulnerabilityException.vulnerability_id == vulnerability_id,
                    VulnerabilityException.host_id == host_id,
                    VulnerabilityException.exception_type == 'vulnerability_host'
                )
            )
        )
    else:
        # Check only for vulnerability-specific exceptions
        query = query.filter(
            and_(
                VulnerabilityException.vulnerability_id == vulnerability_id,
                VulnerabilityException.exception_type == 'vulnerability'
            )
        )
    
    exception = query.first()
    if exception:
        return {
            "exception_id": exception.exception_id,
            "exception_type": exception.exception_type,
            "reason": exception.reason,
            "expiry_date": exception.expiry_date.isoformat(),
            "created_by": exception.created_by,
            "is_expired": exception.is_expired
        }
    
    return None


def should_exclude_vulnerability_from_counts(session: Session, vulnerability_id: int):
    """
    Determine if a vulnerability should be excluded from counts based on exception rules:
    - If there's a vulnerability exception: exclude immediately
    - If there are only vulnerability-host exceptions: exclude only if ALL hosts are closed or have exceptions
    
    Args:
        session: Database session
        vulnerability_id: Vulnerability plugin ID
        
    Returns:
        bool: True if vulnerability should be excluded from counts
    """
    current_date = date.today()
    
    # Check for vulnerability-wide exception (exclude immediately)
    vuln_exception = session.query(VulnerabilityException).filter(
        and_(
            VulnerabilityException.vulnerability_id == vulnerability_id,
            VulnerabilityException.exception_type == 'vulnerability',
            VulnerabilityException.is_active == True,
            VulnerabilityException.expiry_date >= current_date
        )
    ).first()
    
    if vuln_exception:
        return True
    
    # Check if all hosts for this vulnerability are either closed or have exceptions
    from models.vuln import host_vulnerability
    
    # Get all hosts with this vulnerability
    total_hosts = session.query(host_vulnerability.c.host_id).filter(
        host_vulnerability.c.vulnerability_id == vulnerability_id,
        host_vulnerability.c.vuln_status == 'active'
    ).distinct().count()
    
    if total_hosts == 0:
        return True  # No active hosts, exclude
    
    # Count hosts that are either closed or have exceptions
    closed_or_excepted_hosts = 0
    
    # Get all hosts with this vulnerability
    hosts_with_vuln = session.query(host_vulnerability.c.host_id).filter(
        host_vulnerability.c.vulnerability_id == vulnerability_id,
        host_vulnerability.c.vuln_status == 'active'
    ).distinct().all()
    
    for (host_id,) in hosts_with_vuln:
        # Check if host is closed
        host_status = session.query(host_vulnerability.c.vuln_status).filter(
            host_vulnerability.c.host_id == host_id,
            host_vulnerability.c.vulnerability_id == vulnerability_id
        ).scalar()
        
        if host_status != 'active':
            closed_or_excepted_hosts += 1
            continue
        
        # Check if host has any exception (host-specific or vulnerability-host specific)
        host_exception = session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date,
                or_(
                    and_(
                        VulnerabilityException.host_id == host_id,
                        VulnerabilityException.exception_type == 'host'
                    ),
                    and_(
                        VulnerabilityException.vulnerability_id == vulnerability_id,
                        VulnerabilityException.host_id == host_id,
                        VulnerabilityException.exception_type == 'vulnerability_host'
                    )
                )
            )
        ).first()
        
        if host_exception:
            closed_or_excepted_hosts += 1
    
    # Exclude if all hosts are closed or have exceptions
    return closed_or_excepted_hosts >= total_hosts


def get_vulnerability_count_filter_sql():
    """
    Returns SQL condition to exclude vulnerabilities based on the new counting logic.
    This is a complex condition that checks:
    1. Vulnerability-wide exceptions (exclude immediately)
    2. Vulnerability-host exceptions (exclude only if all hosts are closed/excepted)
    
    Returns:
        str: SQL condition for vulnerability counting
    """
    return """
        AND NOT EXISTS (
            -- Exclude if there's a vulnerability-wide exception
            SELECT 1 FROM vulnerability_exceptions ve1
            WHERE ve1.vulnerability_id = v.pluginid
            AND ve1.exception_type = 'vulnerability'
            AND ve1.is_active = true
            AND ve1.expiry_date >= CURRENT_DATE
        )
        AND NOT (
            -- Exclude if all hosts are closed or have exceptions
            EXISTS (
                SELECT 1 FROM host_vulnerability hv
                WHERE hv.vulnerability_id = v.pluginid
            )
            AND NOT EXISTS (
                SELECT 1 FROM host_vulnerability hv2
                WHERE hv2.vulnerability_id = v.pluginid
                AND hv2.vuln_status = 'active'
                AND NOT EXISTS (
                    SELECT 1 FROM vulnerability_exceptions ve2
                    WHERE (
                        (ve2.host_id = hv2.host_id AND ve2.exception_type = 'host')
                        OR (ve2.vulnerability_id = v.pluginid AND ve2.host_id = hv2.host_id AND ve2.exception_type = 'vulnerability_host')
                    )
                    AND ve2.is_active = true
                    AND ve2.expiry_date >= CURRENT_DATE
                )
            )
        )
    """

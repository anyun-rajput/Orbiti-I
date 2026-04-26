from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import text, case, func, select, or_
from services.db import SessionLocal
from models.vuln import Host, Vulnerability, host_vulnerability
import pandas as pd
from io import StringIO
from api.scan import get_current_user
from typing import Optional, List

router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/owners/top-vulnerable")
def get_top_vulnerable_owners(
    limit: int = Query(10, ge=1, le=50, description="Number of top owners to return"),
    severity_filter: Optional[List[str]] = Query(None, description="Filter by severity levels: critical, high, medium, low")
):
    """Get top vulnerable owners with optional severity filtering"""
    session: Session = SessionLocal()
    try:
        # Build severity filter condition
        severity_conditions = []
        if severity_filter:
            severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            valid_severities = [severity_map[s.lower()] for s in severity_filter if s.lower() in severity_map]
            if valid_severities:
                severity_conditions = [Vulnerability.severity == s for s in valid_severities]
        
        # Query to get top vulnerable owners
        query = select(
            Host.server_owner.label('owner'),
            func.count(func.distinct(host_vulnerability.c.vulnerability_id)).label('total'),
            func.count(func.distinct(case((Vulnerability.severity == 4, host_vulnerability.c.vulnerability_id)))).label('critical'),
            func.count(func.distinct(case((Vulnerability.severity == 3, host_vulnerability.c.vulnerability_id)))).label('high'),
            func.count(func.distinct(case((Vulnerability.severity == 2, host_vulnerability.c.vulnerability_id)))).label('medium'),
            func.count(func.distinct(case((Vulnerability.severity == 1, host_vulnerability.c.vulnerability_id)))).label('low'),
            func.count(func.distinct(Host.id)).label('affected_hosts')
        ).select_from(
            Host.join(host_vulnerability, Host.id == host_vulnerability.c.host_id)
                 .join(Vulnerability, host_vulnerability.c.vulnerability_id == Vulnerability.pluginid)
        ).where(
            Host.server_owner.isnot(None),
            Host.server_owner != '',
            host_vulnerability.c.vuln_status == 'active',
            or_(*severity_conditions) if severity_conditions else Vulnerability.severity >= 1
        ).group_by(Host.server_owner).having(
            func.count(func.distinct(host_vulnerability.c.vulnerability_id)) > 0
        ).order_by(
            func.count(func.distinct(host_vulnerability.c.vulnerability_id)).desc(),
            func.count(func.distinct(case((Vulnerability.severity == 4, host_vulnerability.c.vulnerability_id)))).desc(),
            func.count(func.distinct(case((Vulnerability.severity == 3, host_vulnerability.c.vulnerability_id)))).desc()
        ).limit(limit)
        
        results = session.execute(query).fetchall()
        
        owners = []
        for row in results:
            owners.append({
                "owner": row.owner,
                "total": row.total or 0,
                "critical": row.critical or 0,
                "high": row.high or 0,
                "medium": row.medium or 0,
                "low": row.low or 0,
                "affected_hosts": row.affected_hosts or 0
            })
        
        return {
            "owners": owners,
            "total_count": len(owners),
            "filters_applied": {
                "limit": limit,
                "severity_filter": severity_filter or ["all"]
            }
        }
    finally:
        session.close()

@router.get("/owners/{owner_name}/details")
def get_owner_details(owner_name: str):
    """Get detailed information about a specific owner including all their hosts"""
    session: Session = SessionLocal()
    try:
        # Check if owner exists
        owner_check = session.query(Host).filter(Host.server_owner == owner_name).first()
        if not owner_check:
            raise HTTPException(status_code=404, detail="Owner not found")
        
        # Get owner vulnerability statistics using proper SQL query
        owner_stats_query = """
            SELECT 
                COUNT(DISTINCT hv.vulnerability_id) as total_vulnerabilities,
                COUNT(DISTINCT hv.vulnerability_id) as total_instances,
                COUNT(DISTINCT h.id) as affected_hosts,
                COUNT(DISTINCT CASE WHEN v.severity = 4 THEN hv.vulnerability_id END) as critical_count,
                COUNT(DISTINCT CASE WHEN v.severity = 3 THEN hv.vulnerability_id END) as high_count,
                COUNT(DISTINCT CASE WHEN v.severity = 2 THEN hv.vulnerability_id END) as medium_count,
                COUNT(DISTINCT CASE WHEN v.severity = 1 THEN hv.vulnerability_id END) as low_count,
                MAX(h.last_scan_date) as last_scan_date
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE h.server_owner = :owner_name
            AND hv.vuln_status = 'active'
            AND v.severity >= 1
        """
        
        stats_result = session.execute(text(owner_stats_query), {"owner_name": owner_name}).first()
        
        # Get host summaries with their vulnerability statistics (only hosts with vulnerabilities)
        hosts_query = """
            SELECT 
                h.id,
                h.hostname,
                h.host_ip,
                h.os_name,
                h.status,
                h.last_scan_date,
                COUNT(DISTINCT hv.vulnerability_id) as vulnerability_count,
                COUNT(DISTINCT CASE WHEN v.severity = 4 THEN hv.vulnerability_id END) as critical_count,
                COUNT(DISTINCT CASE WHEN v.severity = 3 THEN hv.vulnerability_id END) as high_count,
                COUNT(DISTINCT CASE WHEN v.severity = 2 THEN hv.vulnerability_id END) as medium_count,
                COUNT(DISTINCT CASE WHEN v.severity = 1 THEN hv.vulnerability_id END) as low_count
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id AND hv.vuln_status = 'active'
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid AND v.severity >= 1
            WHERE h.server_owner = :owner_name
            GROUP BY h.id, h.hostname, h.host_ip, h.os_name, h.status, h.last_scan_date
            HAVING COUNT(DISTINCT hv.vulnerability_id) > 0
            ORDER BY vulnerability_count DESC, critical_count DESC
        """
        
        hosts_results = session.execute(text(hosts_query), {"owner_name": owner_name}).fetchall()
        
        host_summaries = []
        for row in hosts_results:
            host_summaries.append({
                "id": row.id,
                "hostname": row.hostname,
                "host_ip": row.host_ip,
                "os_name": row.os_name,
                "status": row.status,
                "vulnerability_count": row.vulnerability_count or 0,
                "last_scan_date": row.last_scan_date.isoformat() if row.last_scan_date else None,
                "severity_breakdown": {
                    "critical": row.critical_count or 0,
                    "high": row.high_count or 0,
                    "medium": row.medium_count or 0,
                    "low": row.low_count or 0
                }
            })
        
        return {
            "owner_name": owner_name,
            "total_vulnerabilities": stats_result.total_vulnerabilities or 0,
            "total_instances": stats_result.total_instances or 0,
            "affected_hosts": stats_result.affected_hosts or 0,
            "severity_breakdown": {
                "critical": stats_result.critical_count or 0,
                "high": stats_result.high_count or 0,
                "medium": stats_result.medium_count or 0,
                "low": stats_result.low_count or 0
            },
            "last_scan_date": stats_result.last_scan_date.isoformat() if stats_result.last_scan_date else None,
            "hosts": host_summaries
        }
    finally:
        session.close()


@router.get("/owners/{owner_name}/export_csv")
def export_owner_vulnerabilities_csv(owner_name: str):
    """Export all vulnerabilities for a specific owner as CSV"""
    session: Session = SessionLocal()
    try:
        # Get all hosts for this owner
        hosts = session.query(Host).filter(Host.server_owner == owner_name).all()
        if not hosts:
            raise HTTPException(status_code=404, detail="Owner not found")
        
        host_ids = [host.id for host in hosts]
        
        # Get all vulnerabilities with comments for these hosts using raw SQL
        query = text("""
            SELECT 
                h.hostname,
                h.host_ip,
                h.os_name,
                h.application_dependent,
                h.status,
                h.last_scan_date,
                v.id,
                v.pluginname,
                v.severity,
                v.description,
                v.solution,
                v.cpe,
                hv.vuln_status,
                hv.plugin_output,
                GROUP_CONCAT(
                    CONCAT(
                        '[', c.comment_type, '] ',
                        c.content, 
                        ' (by ', c.created_by, ' on ', 
                        DATE_FORMAT(c.created_at, '%Y-%m-%d %H:%i'), ')'
                    ) 
                    SEPARATOR ' | '
                ) as comments
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            LEFT JOIN comments c ON (
                (c.comment_type = 'vulnerability' AND c.vulnerability_id = v.pluginid) OR
                (c.comment_type = 'host' AND c.host_id = h.id) OR
                (c.comment_type = 'host_vulnerability' AND c.host_id = h.id AND c.vulnerability_id = v.pluginid)
            )
            WHERE h.id IN :host_ids
            GROUP BY h.id, v.id, h.hostname, h.host_ip, h.os_name, h.application_dependent,
                     h.status, h.last_scan_date, v.pluginname, v.severity, v.description,
                     v.solution, v.cpe, hv.vuln_status, hv.plugin_output
            ORDER BY v.severity DESC, h.hostname, v.pluginname
        """)
        
        results = session.execute(query, {"host_ids": tuple(host_ids)}).fetchall()
        
        # Create DataFrame
        data = []
        severity_map = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        
        for result in results:
            data.append({
                "Owner": owner_name,
                "Host": result.hostname,
                "IP Address": result.host_ip,
                "OS": result.os_name or "Unknown",
                "Application": result.application_dependent or "Not specified",
                "Host Status": result.status,
                "Vulnerability ID": result.id,
                "Vulnerability Name": result.pluginname,
                "Severity": severity_map.get(result.severity, "Unknown"),
                "Description": result.description,
                "Solution": result.solution,
                "CVE": result.cpe or "N/A",
                "Status": result.vuln_status,
                "Plugin Output": result.plugin_output or "N/A",
                "Last Scan": result.last_scan_date.isoformat() if result.last_scan_date else "Never",
                "Comments": result.comments or ""
            })
        
        df = pd.DataFrame(data)
        
        # Create CSV string
        csv_buffer = StringIO()
        df.to_csv(csv_buffer, index=False)
        csv_content = csv_buffer.getvalue()
        
        # Return as streaming response
        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=owner_{owner_name}_vulnerabilities.csv"}
        )
    finally:
        session.close()

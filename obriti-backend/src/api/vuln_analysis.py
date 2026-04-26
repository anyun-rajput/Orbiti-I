from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from services.db import SessionLocal
from models.vuln import Vulnerability, Host, host_vulnerability
from sqlalchemy import text, func, desc
from fastapi.responses import StreamingResponse
from api.scan import get_current_user
from typing import List, Optional
import csv
from io import StringIO

router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/vulnerabilities/by_owner")
def get_vulnerabilities_by_owner(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str = Query("", alias="search"),
    severity: str = Query("all", alias="severity"),
    owner: str = Query("all", alias="owner")
):
    """
    Get vulnerabilities grouped by server owner with detailed statistics.
    Returns vulnerability counts and severity breakdown for each owner.
    """
    session: Session = SessionLocal()
    try:
        severity_map = {
            1: "low",
            2: "medium", 
            3: "high",
            4: "critical"
        }
        reverse_severity_map = {v: k for k, v in severity_map.items()}

        # Base query for vulnerability analysis by owner
        base_query = """
            SELECT 
                h.server_owner,
                COUNT(DISTINCT hv.vulnerability_id) as total_vulnerabilities,
                COUNT(hv.vulnerability_id) as total_instances,
                COUNT(DISTINCT h.id) as affected_hosts,
                COUNT(DISTINCT CASE WHEN v.severity = 4 THEN hv.vulnerability_id END) as critical_count,
                COUNT(DISTINCT CASE WHEN v.severity = 3 THEN hv.vulnerability_id END) as high_count,
                COUNT(DISTINCT CASE WHEN v.severity = 2 THEN hv.vulnerability_id END) as medium_count,
                COUNT(DISTINCT CASE WHEN v.severity = 1 THEN hv.vulnerability_id END) as low_count,
                MAX(h.last_scan_date) as last_scan_date
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE hv.vuln_status = 'active'
            AND v.severity >= 1
            AND NOT EXISTS (
                -- Exclude if there's a vulnerability-wide exception
                SELECT 1 FROM vulnerability_exceptions ve1
                WHERE ve1.vulnerability_id = v.pluginid
                AND ve1.exception_type = 'vulnerability'
                AND ve1.is_active = true
                AND ve1.expiry_date >= CURRENT_DATE
            )
            AND NOT EXISTS (
                -- Exclude if there's a host-specific exception
                SELECT 1 FROM vulnerability_exceptions ve2
                WHERE ve2.host_id = h.id
                AND ve2.exception_type = 'host'
                AND ve2.is_active = true
                AND ve2.expiry_date >= CURRENT_DATE
            )
            AND NOT EXISTS (
                -- Exclude if there's a vulnerability-host specific exception
                SELECT 1 FROM vulnerability_exceptions ve3
                WHERE ve3.vulnerability_id = v.pluginid
                AND ve3.host_id = h.id
                AND ve3.exception_type = 'vulnerability_host'
                AND ve3.is_active = true
                AND ve3.expiry_date >= CURRENT_DATE
            )
        """

        # Add filters
        params = {}
        
        if search:
            base_query += " AND (LOWER(h.server_owner) LIKE LOWER(:search) OR LOWER(h.hostname) LIKE LOWER(:search))"
            params["search"] = f"%{search}%"
        
        if severity != "all" and severity in reverse_severity_map:
            base_query += " AND v.severity = :severity_value"
            params["severity_value"] = reverse_severity_map[severity]
        
        if owner != "all":
            base_query += " AND h.server_owner = :owner"
            params["owner"] = owner

        # Group by owner and add pagination
        base_query += """
            GROUP BY h.server_owner
            HAVING h.server_owner IS NOT NULL AND h.server_owner != '' 
            AND COUNT(DISTINCT hv.vulnerability_id) > 0
            ORDER BY total_instances DESC, critical_count DESC, high_count DESC
            LIMIT :limit OFFSET :offset
        """
        
        params.update({
            "limit": page_size,
            "offset": (page - 1) * page_size
        })

        results = session.execute(text(base_query), params).fetchall()
        
        # Process results
        owner_analysis = []
        for row in results:
            owner_analysis.append({
                "owner": row.server_owner,
                "total_vulnerabilities": row.total_vulnerabilities,
                "total_instances": row.total_instances,
                "affected_hosts": row.affected_hosts,
                "severity_breakdown": {
                    "critical": row.critical_count,
                    "high": row.high_count,
                    "medium": row.medium_count,
                    "low": row.low_count
                },
                "last_scan_date": row.last_scan_date.isoformat() if row.last_scan_date else None
            })

        # Get total count for pagination
        count_query = """
            SELECT COUNT(DISTINCT h.server_owner) as total
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE hv.vuln_status = 'active'
            AND v.severity >= 1
            AND h.server_owner IS NOT NULL 
            AND h.server_owner != ''
        """
        
        count_params = {}
        if search:
            count_query += " AND (LOWER(h.server_owner) LIKE LOWER(:search) OR LOWER(h.hostname) LIKE LOWER(:search))"
            count_params["search"] = f"%{search}%"
        
        if severity != "all" and severity in reverse_severity_map:
            count_query += " AND v.severity = :severity_value"
            count_params["severity_value"] = reverse_severity_map[severity]
        
        if owner != "all":
            count_query += " AND h.server_owner = :owner"
            count_params["owner"] = owner

        total_result = session.execute(text(count_query), count_params).scalar()
        total = total_result or 0

        return {
            "owners": owner_analysis,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size
        }
    finally:
        session.close()


@router.get("/vulnerabilities/by_hosts")
def get_vulnerabilities_by_hosts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str = Query("", alias="search"),
    severity: str = Query("all", alias="severity"),
    owner: str = Query("all", alias="owner"),
    sort_by: str = Query("total_vulnerabilities", alias="sort_by")  # total_vulnerabilities, hostname
):
    """
    Get vulnerabilities grouped by individual hosts with detailed statistics.
    Returns vulnerability counts and severity breakdown for each host.
    """
    session: Session = SessionLocal()
    try:
        severity_map = {
            1: "low",
            2: "medium",
            3: "high", 
            4: "critical"
        }
        reverse_severity_map = {v: k for k, v in severity_map.items()}

        # Base query for vulnerability analysis by hosts
        base_query = """
            SELECT 
                h.id,
                h.hostname,
                h.host_ip,
                h.server_owner,
                h.application_dependent,
                h.os_name,
                h.status,
                h.last_scan_date,
                h.ready_for_rescan,
                COUNT(DISTINCT hv.vulnerability_id) as total_vulnerabilities,
                COUNT(hv.vulnerability_id) as total_instances,
                COUNT(CASE WHEN v.severity = 4 THEN 1 END) as critical_count,
                COUNT(CASE WHEN v.severity = 3 THEN 1 END) as high_count,
                COUNT(CASE WHEN v.severity = 2 THEN 1 END) as medium_count,
                COUNT(CASE WHEN v.severity = 1 THEN 1 END) as low_count
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE hv.vuln_status = 'active'
            AND v.severity >= 1
            AND NOT EXISTS (
                -- Exclude if there's a vulnerability-wide exception
                SELECT 1 FROM vulnerability_exceptions ve1
                WHERE ve1.vulnerability_id = v.pluginid
                AND ve1.exception_type = 'vulnerability'
                AND ve1.is_active = true
                AND ve1.expiry_date >= CURRENT_DATE
            )
            AND NOT EXISTS (
                -- Exclude if there's a host-specific exception
                SELECT 1 FROM vulnerability_exceptions ve2
                WHERE ve2.host_id = h.id
                AND ve2.exception_type = 'host'
                AND ve2.is_active = true
                AND ve2.expiry_date >= CURRENT_DATE
            )
            AND NOT EXISTS (
                -- Exclude if there's a vulnerability-host specific exception
                SELECT 1 FROM vulnerability_exceptions ve3
                WHERE ve3.vulnerability_id = v.pluginid
                AND ve3.host_id = h.id
                AND ve3.exception_type = 'vulnerability_host'
                AND ve3.is_active = true
                AND ve3.expiry_date >= CURRENT_DATE
            )
        """

        # Add filters
        params = {}
        
        if search:
            base_query += " AND (LOWER(h.hostname) LIKE LOWER(:search) OR LOWER(h.host_ip) LIKE LOWER(:search) OR LOWER(h.server_owner) LIKE LOWER(:search))"
            params["search"] = f"%{search}%"
        
        if severity != "all" and severity in reverse_severity_map:
            base_query += " AND v.severity = :severity_value"
            params["severity_value"] = reverse_severity_map[severity]
        
        if owner != "all":
            base_query += " AND h.server_owner = :owner"
            params["owner"] = owner

        # Group by host and filter out hosts with no vulnerabilities
        base_query += " GROUP BY h.id, h.hostname, h.host_ip, h.server_owner, h.application_dependent, h.os_name, h.status, h.last_scan_date, h.ready_for_rescan"
        base_query += " HAVING COUNT(DISTINCT hv.vulnerability_id) > 0"
        
        # Add sorting
        if sort_by == "hostname":
            base_query += " ORDER BY h.hostname ASC"
        else:  # total_vulnerabilities (default)
            base_query += " ORDER BY total_vulnerabilities DESC, critical_count DESC"
        
        # Add pagination
        base_query += " LIMIT :limit OFFSET :offset"
        
        params.update({
            "limit": page_size,
            "offset": (page - 1) * page_size
        })

        results = session.execute(text(base_query), params).fetchall()
        
        # Process results
        host_analysis = []
        for row in results:
            host_analysis.append({
                "id": row.id,
                "hostname": row.hostname,
                "host_ip": row.host_ip,
                "server_owner": row.server_owner,
                "application_dependent": row.application_dependent,
                "os_name": row.os_name or "Unknown",
                "status": row.status,
                "last_scan_date": row.last_scan_date.isoformat() if row.last_scan_date else None,
                "ready_for_rescan": row.ready_for_rescan,
                "total_vulnerabilities": row.total_vulnerabilities,
                "total_instances": row.total_instances,
                "severity_breakdown": {
                    "critical": row.critical_count,
                    "high": row.high_count,
                    "medium": row.medium_count,
                    "low": row.low_count
                }
            })

        # Get total count for pagination
        count_query = """
            SELECT COUNT(DISTINCT h.id) as total
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE hv.vuln_status = 'active'
            AND v.severity >= 1
        """
        
        count_params = {}
        if search:
            count_query += " AND (LOWER(h.hostname) LIKE LOWER(:search) OR LOWER(h.host_ip) LIKE LOWER(:search) OR LOWER(h.server_owner) LIKE LOWER(:search))"
            count_params["search"] = f"%{search}%"
        
        if severity != "all" and severity in reverse_severity_map:
            count_query += " AND v.severity = :severity_value"
            count_params["severity_value"] = reverse_severity_map[severity]
        
        if owner != "all":
            count_query += " AND h.server_owner = :owner"
            count_params["owner"] = owner

        total_result = session.execute(text(count_query), count_params).scalar()
        total = total_result or 0

        return {
            "hosts": host_analysis,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size
        }
    finally:
        session.close()


@router.get("/vulnerabilities/owner_summary")
def get_owner_summary():
    """
    Get a summary of all owners with their vulnerability statistics.
    Used for dropdowns and quick overview.
    """
    session: Session = SessionLocal()
    try:
        summary_query = """
            SELECT 
                h.server_owner,
                COUNT(DISTINCT h.id) as total_hosts,
                COUNT(DISTINCT hv.vulnerability_id) as unique_vulnerabilities,
                COUNT(DISTINCT hv.vulnerability_id) as total_instances,
                COUNT(DISTINCT CASE WHEN v.severity = 4 THEN hv.vulnerability_id END) as critical_count,
                COUNT(DISTINCT CASE WHEN v.severity = 3 THEN hv.vulnerability_id END) as high_count,
                COUNT(DISTINCT CASE WHEN v.severity = 2 THEN hv.vulnerability_id END) as medium_count,
                COUNT(DISTINCT CASE WHEN v.severity = 1 THEN hv.vulnerability_id END) as low_count
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE hv.vuln_status = 'active'
            AND v.severity >= 1
            AND h.server_owner IS NOT NULL 
            AND h.server_owner != ''
            AND NOT EXISTS (
                -- Exclude if there's a vulnerability-wide exception
                SELECT 1 FROM vulnerability_exceptions ve1
                WHERE ve1.vulnerability_id = v.pluginid
                AND ve1.exception_type = 'vulnerability'
                AND ve1.is_active = true
                AND ve1.expiry_date >= CURRENT_DATE
            )
            AND NOT EXISTS (
                -- Exclude if there's a host-specific exception
                SELECT 1 FROM vulnerability_exceptions ve2
                WHERE ve2.host_id = h.id
                AND ve2.exception_type = 'host'
                AND ve2.is_active = true
                AND ve2.expiry_date >= CURRENT_DATE
            )
            AND NOT EXISTS (
                -- Exclude if there's a vulnerability-host specific exception
                SELECT 1 FROM vulnerability_exceptions ve3
                WHERE ve3.vulnerability_id = v.pluginid
                AND ve3.host_id = h.id
                AND ve3.exception_type = 'vulnerability_host'
                AND ve3.is_active = true
                AND ve3.expiry_date >= CURRENT_DATE
            )
            GROUP BY h.server_owner
            HAVING COUNT(DISTINCT hv.vulnerability_id) > 0
            ORDER BY total_instances DESC
        """
        
        results = session.execute(text(summary_query)).fetchall()
        
        owners = []
        for row in results:
            owners.append({
                "name": row.server_owner,
                "total_hosts": row.total_hosts,
                "unique_vulnerabilities": row.unique_vulnerabilities,
                "total_instances": row.total_instances,
                "severity_counts": {
                    "critical": row.critical_count,
                    "high": row.high_count,
                    "medium": row.medium_count,
                    "low": row.low_count
                }
            })

        return {"owners": owners}
    finally:
        session.close()


@router.get("/vulnerabilities/by_owner/export_csv")
def export_vulnerabilities_by_owner_csv():
    """
    Export vulnerability analysis by owner to CSV format.
    """
    session: Session = SessionLocal()
    
    def csv_generator():
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Server Owner", "Total Hosts", "Total Vulnerabilities", "Total Instances",
            "Critical Count", "High Count", "Medium Count", "Low Count", 
            "Last Scan Date"
        ])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        query = """
            SELECT 
                h.server_owner,
                COUNT(DISTINCT h.id) as total_hosts,
                COUNT(DISTINCT hv.vulnerability_id) as total_vulnerabilities,
                COUNT(hv.vulnerability_id) as total_instances,
                COUNT(DISTINCT CASE WHEN v.severity = 4 THEN hv.vulnerability_id END) as critical_count,
                COUNT(DISTINCT CASE WHEN v.severity = 3 THEN hv.vulnerability_id END) as high_count,
                COUNT(DISTINCT CASE WHEN v.severity = 2 THEN hv.vulnerability_id END) as medium_count,
                COUNT(DISTINCT CASE WHEN v.severity = 1 THEN hv.vulnerability_id END) as low_count,
                MAX(h.last_scan_date) as last_scan_date
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE hv.vuln_status = 'active'
            AND v.severity >= 1
            AND h.server_owner IS NOT NULL 
            AND h.server_owner != ''
            GROUP BY h.server_owner
            HAVING COUNT(DISTINCT hv.vulnerability_id) > 0
            ORDER BY total_instances DESC
        """
        
        results = session.execute(text(query)).fetchall()
        
        for row in results:
            writer.writerow([
                row.server_owner,
                row.total_hosts,
                row.total_vulnerabilities,
                row.total_instances,
                row.critical_count,
                row.high_count,
                row.medium_count,
                row.low_count,
                row.last_scan_date.isoformat() if row.last_scan_date else ""
            ])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
        
        session.close()

    return StreamingResponse(
        csv_generator(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities_by_owner.csv"}
    )


@router.get("/vulnerabilities/by_hosts/export_csv")
def export_vulnerabilities_by_hosts_csv():
    """
    Export vulnerability analysis by hosts to CSV format.
    """
    session: Session = SessionLocal()
    
    def csv_generator():
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Hostname", "Host IP", "Server Owner", "Application Dependent", "OS Name", "Status",
            "Total Vulnerabilities", "Total Instances", "Critical Count", "High Count", 
            "Medium Count", "Low Count", "Last Scan Date"
        ])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        query = """
            SELECT 
                h.hostname,
                h.host_ip,
                h.server_owner,
                h.application_dependent,
                h.os_name,
                h.status,
                h.last_scan_date,
                COUNT(DISTINCT hv.vulnerability_id) as total_vulnerabilities,
                COUNT(hv.vulnerability_id) as total_instances,
                COUNT(CASE WHEN v.severity = 4 THEN 1 END) as critical_count,
                COUNT(CASE WHEN v.severity = 3 THEN 1 END) as high_count,
                COUNT(CASE WHEN v.severity = 2 THEN 1 END) as medium_count,
                COUNT(CASE WHEN v.severity = 1 THEN 1 END) as low_count
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE hv.vuln_status = 'active'
            AND v.severity >= 1
            GROUP BY h.id, h.hostname, h.host_ip, h.server_owner, h.application_dependent, h.os_name, h.status, h.last_scan_date
            HAVING COUNT(DISTINCT hv.vulnerability_id) > 0
            ORDER BY total_vulnerabilities DESC, critical_count DESC
        """
        
        results = session.execute(text(query)).fetchall()
        
        for row in results:
            writer.writerow([
                row.hostname,
                row.host_ip,
                row.server_owner or "",
                row.application_dependent or "",
                row.os_name or "Unknown",
                row.status,
                row.total_vulnerabilities,
                row.total_instances,
                row.critical_count,
                row.high_count,
                row.medium_count,
                row.low_count,
                row.last_scan_date.isoformat() if row.last_scan_date else ""
            ])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
        
        session.close()

    return StreamingResponse(
        csv_generator(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities_by_hosts.csv"}
    )


@router.get("/hosts/{host_id}/details")
def get_host_details(host_id: int):
    """
    Get detailed information about a specific host including all its vulnerabilities.
    """
    session: Session = SessionLocal()
    try:
        # Get host basic information
        host = session.query(Host).filter(Host.id == host_id).first()
        if not host:
            return {"error": "Host not found"}

        # Get host vulnerabilities with details
        vulnerabilities_query = """
            SELECT 
                v.pluginid as id,
                v.pluginname as name,
                v.severity,
                v.description,
                v.solution,
                v.cpe as cve,
                hv.plugin_output,
                hv.vuln_status
            FROM vulnerabilities v
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
            WHERE hv.host_id = :host_id
            AND hv.vuln_status = 'active'
            ORDER BY v.severity DESC, v.pluginname ASC
        """
        
        vuln_results = session.execute(text(vulnerabilities_query), {"host_id": host_id}).fetchall()
        
        severity_map = {
            1: "low",
            2: "medium",
            3: "high",
            4: "critical"
        }
        
        vulnerabilities = []
        for row in vuln_results:
            vulnerabilities.append({
                "id": str(row.id),
                "name": row.name,
                "severity": severity_map.get(row.severity, "unknown"),
                "description": row.description,
                "solution": row.solution,
                "cve": row.cve,
                "plugin_output": row.plugin_output,
                "vuln_status": row.vuln_status
            })

        return {
            "id": host.id,
            "hostname": host.hostname,
            "host_ip": host.host_ip,
            "server_owner": host.server_owner,
            "application_dependent": host.application_dependent,
            "os_name": host.os_name,
            "status": host.status,
            "last_scan_date": host.last_scan_date.isoformat() if host.last_scan_date else None,
            "vulnerabilities": vulnerabilities
        }
    finally:
        session.close()


@router.get("/vulnerabilities/owner/{owner_name}/details")
def get_owner_details(owner_name: str):
    """
    Get detailed information about a specific owner including all hosts and top vulnerabilities.
    """
    session: Session = SessionLocal()
    try:
        # Get owner summary
        owner_summary_query = """
            SELECT 
                h.server_owner,
                COUNT(DISTINCT h.id) as total_hosts,
                COUNT(DISTINCT hv.vulnerability_id) as total_vulnerabilities,
                COUNT(hv.host_id) as total_instances,
                SUM(CASE WHEN v.severity = 4 THEN 1 ELSE 0 END) as critical_count,
                SUM(CASE WHEN v.severity = 3 THEN 1 ELSE 0 END) as high_count,
                SUM(CASE WHEN v.severity = 2 THEN 1 ELSE 0 END) as medium_count,
                SUM(CASE WHEN v.severity = 1 THEN 1 ELSE 0 END) as low_count
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE h.server_owner = :owner_name
            AND hv.vuln_status = 'active'
            AND v.severity >= 1
            GROUP BY h.server_owner
        """
        
        owner_result = session.execute(text(owner_summary_query), {"owner_name": owner_name}).first()
        
        if not owner_result:
            return {"error": "Owner not found or has no vulnerabilities"}

        # Get all hosts for this owner with their vulnerability stats
        hosts_query = """
            SELECT 
                h.id,
                h.hostname,
                h.host_ip,
                h.os_name,
                h.status,
                h.last_scan_date,
                COUNT(DISTINCT hv.vulnerability_id) as vulnerability_count,
                SUM(CASE WHEN v.severity = 4 THEN 1 
                    WHEN v.severity = 3 THEN 1 
                    WHEN v.severity = 2 THEN 1 
                    WHEN v.severity = 1 THEN 1 
                    ELSE 0 END) as total_vuln_instances
            FROM hosts h
            LEFT JOIN host_vulnerability hv ON h.id = hv.host_id AND hv.vuln_status = 'active'
            LEFT JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid AND v.severity >= 1
            WHERE h.server_owner = :owner_name
            GROUP BY h.id, h.hostname, h.host_ip, h.os_name, h.status, h.last_scan_date
            ORDER BY vulnerability_count DESC, total_vuln_instances DESC
        """
        
        hosts_results = session.execute(text(hosts_query), {"owner_name": owner_name}).fetchall()
        
        hosts = []
        for row in hosts_results:
            hosts.append({
                "id": row.id,
                "hostname": row.hostname,
                "host_ip": row.host_ip,
                "os_name": row.os_name or "Unknown",
                "status": row.status,
                "vulnerability_count": row.vulnerability_count or 0,
                "last_scan_date": row.last_scan_date.isoformat() if row.last_scan_date else None
            })

        # Get top vulnerabilities for this owner
        top_vulns_query = """
            SELECT 
                v.pluginid as id,
                v.pluginname as name,
                v.severity,
                v.cpe as cve,
                COUNT(DISTINCT hv.host_id) as affected_hosts
            FROM vulnerabilities v
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
            INNER JOIN hosts h ON hv.host_id = h.id
            WHERE h.server_owner = :owner_name
            AND hv.vuln_status = 'active'
            AND v.severity >= 1
            GROUP BY v.pluginid, v.pluginname, v.severity, v.cpe
            ORDER BY v.severity DESC, affected_hosts DESC
            LIMIT 10
        """
        
        vuln_results = session.execute(text(top_vulns_query), {"owner_name": owner_name}).fetchall()
        
        severity_map = {
            1: "low",
            2: "medium",
            3: "high",
            4: "critical"
        }
        
        top_vulnerabilities = []
        for row in vuln_results:
            top_vulnerabilities.append({
                "id": str(row.id),
                "name": row.name,
                "severity": severity_map.get(row.severity, "unknown"),
                "affected_hosts": row.affected_hosts,
                "cve": row.cve
            })

        return {
            "owner": owner_name,
            "total_hosts": owner_result.total_hosts,
            "total_vulnerabilities": owner_result.total_vulnerabilities,
            "total_instances": owner_result.total_instances,
            "severity_breakdown": {
                "critical": owner_result.critical_count,
                "high": owner_result.high_count,
                "medium": owner_result.medium_count,
                "low": owner_result.low_count
            },
            "hosts": hosts,
            "top_vulnerabilities": top_vulnerabilities
        }
    finally:
        session.close()


@router.get("/vulnerabilities/closed")
def get_closed_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str = Query("", alias="search"),
    severity: str = Query("all", alias="severity"),
    owner: str = Query("all", alias="owner"),
    sort_by: str = Query("closed_date", alias="sort_by")  # closed_date, hostname, vulnerability_name
):
    """
    Get vulnerabilities that have been closed, showing which hosts they were closed on.
    Returns detailed information about closed vulnerabilities with host context.
    """
    session: Session = SessionLocal()
    try:
        severity_map = {
            1: "low",
            2: "medium",
            3: "high",
            4: "critical"
        }
        reverse_severity_map = {v: k for k, v in severity_map.items()}

        # Base query for closed vulnerabilities
        base_query = """
            SELECT 
                v.pluginid as vulnerability_id,
                v.pluginname as vulnerability_name,
                v.severity,
                v.description,
                v.solution,
                v.cpe as cve,
                v.cvss_base_score,
                h.id as host_id,
                h.hostname,
                h.host_ip,
                h.server_owner,
                h.application_dependent,
                h.os_name,
                hv.plugin_output,
                hv.closed_date
            FROM vulnerabilities v
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
            INNER JOIN hosts h ON hv.host_id = h.id
            WHERE hv.vuln_status = 'closed'
            AND v.severity >= 1
        """

        # Add filters
        params = {}
        
        if search:
            base_query += " AND (LOWER(v.pluginname) LIKE LOWER(:search) OR LOWER(h.hostname) LIKE LOWER(:search) OR LOWER(h.host_ip) LIKE LOWER(:search) OR LOWER(h.server_owner) LIKE LOWER(:search))"
            params["search"] = f"%{search}%"
        
        if severity != "all" and severity in reverse_severity_map:
            base_query += " AND v.severity = :severity_value"
            params["severity_value"] = reverse_severity_map[severity]
        
        if owner != "all":
            base_query += " AND h.server_owner = :owner"
            params["owner"] = owner

        # Add sorting
        if sort_by == "hostname":
            base_query += " ORDER BY h.hostname ASC, v.pluginname ASC"
        elif sort_by == "vulnerability_name":
            base_query += " ORDER BY v.pluginname ASC, h.hostname ASC"
        else:  # closed_date (default)
            base_query += " ORDER BY hv.closed_date DESC, v.severity DESC, v.pluginname ASC"
        
        # Add pagination
        base_query += " LIMIT :limit OFFSET :offset"
        
        params.update({
            "limit": page_size,
            "offset": (page - 1) * page_size
        })

        results = session.execute(text(base_query), params).fetchall()
        
        # Process results
        closed_vulnerabilities = []
        for row in results:
            closed_vulnerabilities.append({
                "vulnerability_id": str(row.vulnerability_id),
                "vulnerability_name": row.vulnerability_name,
                "severity": severity_map.get(row.severity, "unknown"),
                "description": row.description,
                "solution": row.solution,
                "cve": row.cve,
                "cvss_base_score": row.cvss_base_score,
                "host_id": row.host_id,
                "hostname": row.hostname,
                "host_ip": row.host_ip,
                "server_owner": row.server_owner,
                "application_dependent": row.application_dependent,
                "os_name": row.os_name or "Unknown",
                "plugin_output": row.plugin_output,
                "closed_date": row.closed_date.isoformat() if row.closed_date else None
            })

        # Get total count for pagination
        count_query = """
            SELECT COUNT(*) as total
            FROM vulnerabilities v
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
            INNER JOIN hosts h ON hv.host_id = h.id
            WHERE hv.vuln_status = 'closed'
            AND v.severity >= 1
        """
        
        count_params = {}
        if search:
            count_query += " AND (LOWER(v.pluginname) LIKE LOWER(:search) OR LOWER(h.hostname) LIKE LOWER(:search) OR LOWER(h.host_ip) LIKE LOWER(:search) OR LOWER(h.server_owner) LIKE LOWER(:search))"
            count_params["search"] = f"%{search}%"
        
        if severity != "all" and severity in reverse_severity_map:
            count_query += " AND v.severity = :severity_value"
            count_params["severity_value"] = reverse_severity_map[severity]
        
        if owner != "all":
            count_query += " AND h.server_owner = :owner"
            count_params["owner"] = owner

        total_result = session.execute(text(count_query), count_params).scalar()
        total = total_result or 0

        return {
            "closed_vulnerabilities": closed_vulnerabilities,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size
        }
    finally:
        session.close()


@router.get("/vulnerabilities/closed/summary")
def get_closed_vulnerabilities_summary():
    """
    Get summary statistics for closed vulnerabilities.
    """
    session: Session = SessionLocal()
    try:
        summary_query = """
            SELECT 
                COUNT(DISTINCT v.pluginid) as unique_vulnerabilities,
                COUNT(*) as total_instances,
                COUNT(DISTINCT h.id) as affected_hosts,
                COUNT(DISTINCT h.server_owner) as affected_owners,
                COUNT(CASE WHEN v.severity = 4 THEN 1 END) as critical_count,
                COUNT(CASE WHEN v.severity = 3 THEN 1 END) as high_count,
                COUNT(CASE WHEN v.severity = 2 THEN 1 END) as medium_count,
                COUNT(CASE WHEN v.severity = 1 THEN 1 END) as low_count
            FROM vulnerabilities v
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
            INNER JOIN hosts h ON hv.host_id = h.id
            WHERE hv.vuln_status = 'closed'
            AND v.severity >= 1
        """
        
        result = session.execute(text(summary_query)).first()
        
        return {
            "unique_vulnerabilities": result.unique_vulnerabilities or 0,
            "total_instances": result.total_instances or 0,
            "affected_hosts": result.affected_hosts or 0,
            "affected_owners": result.affected_owners or 0,
            "severity_breakdown": {
                "critical": result.critical_count or 0,
                "high": result.high_count or 0,
                "medium": result.medium_count or 0,
                "low": result.low_count or 0
            }
        }
    finally:
        session.close()


@router.get("/vulnerabilities/closed/export_csv")
def export_closed_vulnerabilities_csv():
    """
    Export closed vulnerabilities to CSV format.
    """
    session: Session = SessionLocal()
    
    def csv_generator():
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Vulnerability ID", "Vulnerability Name", "Severity", "CVE", "CVSS Score",
            "Hostname", "Host IP", "Server Owner", "Application Dependent", "OS Name",
            "Closed Date", "Description", "Solution", "Comments"
        ])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        query = """
            SELECT 
                v.pluginid as vulnerability_id,
                v.pluginname as vulnerability_name,
                v.severity,
                v.cpe as cve,
                v.cvss_base_score,
                h.hostname,
                h.host_ip,
                h.server_owner,
                h.application_dependent,
                h.os_name,
                hv.closed_date,
                v.description,
                v.solution,
                GROUP_CONCAT(
                    CONCAT(
                        '[', c.comment_type, '] ',
                        c.content, 
                        ' (by ', c.created_by, ' on ', 
                        DATE_FORMAT(c.created_at, '%Y-%m-%d %H:%i'), ')'
                    ) 
                    SEPARATOR ' | '
                ) as comments
            FROM vulnerabilities v
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
            INNER JOIN hosts h ON hv.host_id = h.id
            LEFT JOIN comments c ON (
                (c.comment_type = 'vulnerability' AND c.vulnerability_id = v.pluginid) OR
                (c.comment_type = 'host' AND c.host_id = h.id) OR
                (c.comment_type = 'host_vulnerability' AND c.host_id = h.id AND c.vulnerability_id = v.pluginid)
            )
            WHERE hv.vuln_status = 'closed'
            AND v.severity >= 1
            GROUP BY v.pluginid, h.id, v.pluginname, v.severity, v.cpe, v.cvss_base_score,
                     h.hostname, h.host_ip, h.server_owner, h.application_dependent, 
                     h.os_name, hv.closed_date, v.description, v.solution
            ORDER BY hv.closed_date DESC, v.severity DESC, v.pluginname ASC
        """
        
        results = session.execute(text(query)).fetchall()
        
        severity_map = {
            1: "low",
            2: "medium",
            3: "high",
            4: "critical"
        }
        
        for row in results:
            writer.writerow([
                row.vulnerability_id,
                row.vulnerability_name,
                severity_map.get(row.severity, "unknown"),
                row.cve or "",
                row.cvss_base_score or "",
                row.hostname,
                row.host_ip,
                row.server_owner or "",
                row.application_dependent or "",
                row.os_name or "Unknown",
                row.closed_date.isoformat() if row.closed_date else "",
                (row.description or "").replace('\n', ' ').replace('\r', ' '),
                (row.solution or "").replace('\n', ' ').replace('\r', ' '),
                row.comments or ""
            ])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
        
        session.close()

    return StreamingResponse(
        csv_generator(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=closed_vulnerabilities.csv"}
    )


@router.put("/vulnerabilities/{vulnerability_id}/hosts/{host_id}/status")
def update_vulnerability_status(
    vulnerability_id: int,
    host_id: int,
    status: str = Query(..., regex="^(active|closed)$")
):
    """
    Update the status of a specific vulnerability on a specific host.
    Status can be 'active' or 'closed'.
    """
    from datetime import datetime
    
    session: Session = SessionLocal()
    try:
        # Check if the host-vulnerability relationship exists
        result = session.execute(
            text("SELECT * FROM host_vulnerability WHERE host_id = :host_id AND vulnerability_id = :vuln_id"),
            {"host_id": host_id, "vuln_id": vulnerability_id}
        ).first()
        
        if not result:
            return {"error": "Host-vulnerability relationship not found"}
        
        # Update the status and closed_date based on the desired status
        if status == "closed":
            session.execute(
                text("UPDATE host_vulnerability SET vuln_status = :status, closed_date = :closed_date WHERE host_id = :host_id AND vulnerability_id = :vuln_id"),
                {"status": status, "closed_date": datetime.utcnow(), "host_id": host_id, "vuln_id": vulnerability_id}
            )
        else:  # active
            session.execute(
                text("UPDATE host_vulnerability SET vuln_status = :status, closed_date = NULL WHERE host_id = :host_id AND vulnerability_id = :vuln_id"),
                {"status": status, "host_id": host_id, "vuln_id": vulnerability_id}
            )
        
        session.commit()
        
        return {
            "message": f"Vulnerability {vulnerability_id} on host {host_id} status updated to {status}",
            "vulnerability_id": vulnerability_id,
            "host_id": host_id,
            "new_status": status
        }
    except Exception as e:
        session.rollback()
        return {"error": f"Failed to update status: {str(e)}"}
    finally:
        session.close()

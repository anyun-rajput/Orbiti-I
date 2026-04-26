from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from services.db import SessionLocal
from models.vuln import Vulnerability
from sqlalchemy import text, or_, func, case
from fastapi.responses import StreamingResponse
from models.vuln import Host, host_vulnerability
import csv
from io import StringIO
from api.scan import get_current_user
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/vulnerabilities")
def get_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str = Query("", alias="search"),
    severity: str = Query("all", alias="severity")
):
    session: Session = SessionLocal()
    try:
        severity_map = {
            1: "low",
            2: "medium",
            3: "high",
            4: "critical"
        }
        reverse_severity_map = {v: k for k, v in severity_map.items()}

        # Only severity >= 2 (medium, high, critical)
        query = session.query(
            Vulnerability.pluginid.label("id"),
            Vulnerability.pluginname.label("name"),
            Vulnerability.severity,
            Vulnerability.description,
            Vulnerability.solution,
            Vulnerability.cpe.label("cve"),
        ).filter(Vulnerability.severity >= 1)

        # Severity filter
        if severity != "all" and severity in reverse_severity_map:
            query = query.filter(Vulnerability.severity == reverse_severity_map[severity])

        # Search filter
        if search:
            like = f"%{search.lower()}%"
            query = query.filter(
                or_(
                    Vulnerability.pluginname.ilike(like),
                    Vulnerability.cpe.ilike(like),
                    Vulnerability.description.ilike(like)
                )
            )

        # Use SQLAlchemy ORM instead of raw SQL to prevent injection
        query = session.query(
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
        
        # Prepare search term
        search_term = f"%{search}%" if search else None
        
        # Add search filter if provided - using parameterized queries
        if search:
            query = query.filter(
                or_(
                    Vulnerability.pluginname.ilike(search_term),
                    Vulnerability.cpe.ilike(search_term),
                    Vulnerability.description.ilike(search_term),
                    host_vulnerability.c.plugin_output.ilike(search_term)
                )
            )
        
        # Add severity filter if provided
        if severity != "all" and severity in reverse_severity_map:
            query = query.filter(Vulnerability.severity == reverse_severity_map[severity])
        
        # Add grouping and host count - only group by essential columns to avoid sort memory issues
        query = query.add_columns(
            func.count(host_vulnerability.c.host_id).label('host_count')
        ).group_by(
            Vulnerability.pluginid,
            Vulnerability.pluginname,
            Vulnerability.severity,
            Vulnerability.cpe
        )
        
        try:
            # Get total count first - use a simpler count query
            count_query = session.query(func.count(func.distinct(Vulnerability.pluginid))).join(
                host_vulnerability, Vulnerability.pluginid == host_vulnerability.c.vulnerability_id
            ).filter(host_vulnerability.c.vuln_status == 'active')
            
            if search_term:
                count_query = count_query.filter(
                    or_(
                        Vulnerability.pluginname.ilike(search_term),
                        Vulnerability.cpe.ilike(search_term),
                        Vulnerability.description.ilike(search_term),
                        host_vulnerability.c.plugin_output.ilike(search_term)
                    )
                )
            
            if severity != "all" and severity in reverse_severity_map:
                count_query = count_query.filter(Vulnerability.severity == reverse_severity_map[severity])
            
            total = count_query.scalar() or 0
            
            # Get the grouped results without complex sorting
            grouped_results = query.all()
            
            # Sort in Python to avoid MySQL sort memory issues
            def sort_key(row):
                # Create sort key: severity priority (4->3, 3->2, 2->1, 1->0) then host count
                severity_priority = {4: 3, 3: 2, 2: 1, 1: 0}.get(row.severity, 0)
                host_count = row.host_count if hasattr(row, 'host_count') else 0
                return (-severity_priority, -host_count)
            
            # Sort the results
            sorted_results = sorted(grouped_results, key=sort_key)
            
            # Apply pagination
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            vuln_results = sorted_results[start_idx:end_idx]
            
            print(f"Found {len(vuln_results)} vulnerabilities")
                
        except Exception as e:
            print(f"Error executing query: {e}")
            # Return empty result instead of raising
            return {
                "vulnerabilities": [],
                "page": page,
                "page_size": page_size,
                "total": 0,
                "total_pages": 0
            }
        
        # Process results and fetch description/solution separately
        result = []
        for row in vuln_results:
            # Get description and solution for this vulnerability
            vuln_details = session.query(
                Vulnerability.description,
                Vulnerability.solution
            ).filter(Vulnerability.pluginid == row.id).first()
            
            description = vuln_details.description if vuln_details else ""
            solution = vuln_details.solution if vuln_details else ""
            
            result.append({
                "id": str(row.id),
                "name": row.name,
                "severity": severity_map.get(row.severity, "unknown"),
                "hostCount": row.host_count,
                "description": description,
                "solution": solution,
                "cve": row.cve,  # Using CPE as CVE field
                "plugin_output": "",  # Not available in grouped query
                "comment": ""
            })
        
        return {
            "vulnerabilities": result,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size
        }
    finally:
        session.close()


class CloseRequest(BaseModel):
    plugin_id: int = Field(..., description="Vulnerability plugin ID to update")
    host_ids: Optional[List[int]] = Field(None, description="Specific host IDs to target. If omitted, applies to all hosts")
    host_ips: Optional[List[str]] = Field(None, description="Specific host IPs to target. Resolved to host IDs")


class UpdateCloseRequest(CloseRequest):
    status: str = Field("closed", description="Desired status: 'closed' or 'active'")


@router.get("/vulnerabilities/with_hosts")
def get_vulnerabilities_with_hosts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str = Query("", alias="search"),
    severity: str = Query("all", alias="severity")
):
    """
    Get vulnerabilities with their associated host details for proper commenting context.
    Returns individual vulnerability-host pairs instead of aggregated data.
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

        base_query = """
            SELECT 
                v.pluginid as vulnerability_id,
                v.pluginname as vulnerability_name,
                v.severity,
                v.description,
                v.solution,
                v.cpe as cve,
                h.id as host_id,
                h.hostname,
                h.host_ip,
                h.server_owner,
                hv.plugin_output,
                hv.vuln_status,
                h.last_scan_date as detected_date
            FROM vulnerabilities v
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
            INNER JOIN hosts h ON hv.host_id = h.id
            WHERE v.severity >= 1
            AND hv.vuln_status = 'active'
        """
        
        # Add search filter if provided
        if search:
            base_query += """
                AND (
                    LOWER(v.pluginname) LIKE LOWER(:search)
                    OR LOWER(v.cpe) LIKE LOWER(:search)
                    OR LOWER(v.description) LIKE LOWER(:search)
                    OR LOWER(h.hostname) LIKE LOWER(:search)
                    OR LOWER(h.host_ip) LIKE LOWER(:search)
                    OR LOWER(h.server_owner) LIKE LOWER(:search)
                )
            """
        
        # Add severity filter if provided
        if severity != "all" and severity in reverse_severity_map:
            base_query += " AND v.severity = :severity_value"
        
        # Add ordering and pagination
        base_query += """
            ORDER BY 
                CASE v.severity
                    WHEN 4 THEN 3
                    WHEN 3 THEN 2
                    WHEN 2 THEN 1
                    ELSE 0
                END DESC,
                v.pluginname ASC,
                h.hostname ASC
            LIMIT :limit OFFSET :offset
        """
        
        # Execute query with parameters
        params = {
            "limit": page_size,
            "offset": (page - 1) * page_size
        }
        if search:
            params["search"] = f"%{search}%"
        if severity != "all" and severity in reverse_severity_map:
            params["severity_value"] = reverse_severity_map[severity]
        
        vuln_host_results = session.execute(text(base_query), params).fetchall()
        
        # Process results
        result = []
        for row in vuln_host_results:
            result.append({
                "vulnerability_id": str(row.vulnerability_id),
                "vulnerability_name": row.vulnerability_name,
                "severity": severity_map.get(row.severity, "unknown"),
                "description": row.description,
                "solution": row.solution,
                "cve": row.cve,
                "host_id": row.host_id,
                "hostname": row.hostname,
                "host_ip": row.host_ip,
                "server_owner": row.server_owner,
                "plugin_output": row.plugin_output,
                "vuln_status": row.vuln_status,
                "detected_date": row.detected_date.isoformat() if row.detected_date else None
            })
        
        # Get total count for pagination
        count_query = """
            SELECT COUNT(*) as total
            FROM vulnerabilities v
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
            INNER JOIN hosts h ON hv.host_id = h.id
            WHERE v.severity >= 1
            AND hv.vuln_status = 'active'
        """
        
        if search:
            count_query += """
                AND (
                    LOWER(v.pluginname) LIKE LOWER(:search)
                    OR LOWER(v.cpe) LIKE LOWER(:search)
                    OR LOWER(v.description) LIKE LOWER(:search)
                    OR LOWER(h.hostname) LIKE LOWER(:search)
                    OR LOWER(h.host_ip) LIKE LOWER(:search)
                    OR LOWER(h.server_owner) LIKE LOWER(:search)
                )
            """
        
        if severity != "all" and severity in reverse_severity_map:
            count_query += " AND v.severity = :severity_value"
        
        count_params = {}
        if search:
            count_params["search"] = f"%{search}%"
        if severity != "all" and severity in reverse_severity_map:
            count_params["severity_value"] = reverse_severity_map[severity]
        
        total_result = session.execute(text(count_query), count_params).scalar()
        total = total_result or 0
        
        return {
            "vulnerability_hosts": result,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size
        }
    finally:
        session.close()


@router.get("/closed_vulnerabilities")
def get_closed_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str = Query("", alias="search"),
    severity: str = Query("all", alias="severity")
):
    session: Session = SessionLocal()
    try:
        severity_map = {
            2: "medium",
            3: "high",
            4: "critical"
        }
        reverse_severity_map = {v: k for k, v in severity_map.items()}

        base_query = """
            SELECT 
                v.pluginid as id,
                v.pluginname as name,
                v.severity,
                v.description,
                v.solution,
                v.cpe as cve,
                MAX(hv.plugin_output) as plugin_output,
                COUNT(hv.host_id) as host_count
            FROM vulnerabilities v
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
            WHERE v.severity >= 2
            AND hv.vuln_status = 'closed'
        """

        if search:
            base_query += """
                AND (
                    LOWER(v.pluginname) LIKE LOWER(:search)
                    OR LOWER(v.cpe) LIKE LOWER(:search)
                    OR LOWER(v.description) LIKE LOWER(:search)
                    OR LOWER(hv.plugin_output) LIKE LOWER(:search)
                )
            """

        if severity != "all" and severity in reverse_severity_map:
            base_query += " AND v.severity = :severity_value"

        base_query += """
            GROUP BY v.pluginid, v.pluginname, v.severity, v.description, v.solution, v.cpe
            ORDER BY 
                CASE v.severity
                    WHEN 4 THEN 3
                    WHEN 3 THEN 2
                    WHEN 2 THEN 1
                    ELSE 0
                END DESC,
                COUNT(hv.host_id) DESC
            LIMIT :limit OFFSET :offset
        """

        params = {
            "limit": page_size,
            "offset": (page - 1) * page_size
        }
        if search:
            params["search"] = f"%{search}%"
        if severity != "all" and severity in reverse_severity_map:
            params["severity_value"] = reverse_severity_map[severity]

        vuln_results = session.execute(text(base_query), params).fetchall()

        result = []
        for row in vuln_results:
            result.append({
                "id": str(row.id),
                "name": row.name,
                "severity": severity_map.get(row.severity, "unknown"),
                "hostCount": row.host_count,
                "description": row.description,
                "solution": row.solution,
                "cve": row.cve,
                "plugin_output": row.plugin_output,
                "comment": ""
            })

        count_query = """
            SELECT COUNT(DISTINCT v.pluginid) as total
            FROM vulnerabilities v
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
            WHERE v.severity >= 2
            AND hv.vuln_status = 'closed'
        """

        if search:
            count_query += """
                AND (
                    LOWER(v.pluginname) LIKE LOWER(:search)
                    OR LOWER(v.cpe) LIKE LOWER(:search)
                    OR LOWER(v.description) LIKE LOWER(:search)
                )
            """

        if severity != "all" and severity in reverse_severity_map:
            count_query += " AND v.severity = :severity_value"

        count_params = {}
        if search:
            count_params["search"] = f"%{search}%"
        if severity != "all" and severity in reverse_severity_map:
            count_params["severity_value"] = reverse_severity_map[severity]

        total_result = session.execute(text(count_query), count_params).scalar()
        total = total_result or 0

        return {
            "vulnerabilities": result,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size
        }
    finally:
        session.close()


def _resolve_host_ids(session: Session, host_ids: Optional[List[int]], host_ips: Optional[List[str]]) -> List[int]:
    if host_ids:
        return host_ids
    if host_ips:
        rows = session.query(Host.id).filter(Host.host_ip.in_(host_ips)).all()
        return [r.id for r in rows]
    return []


@router.post("/closed_vulnerabilities/mark")
def mark_closed_vulnerabilities(request: CloseRequest):
    session: Session = SessionLocal()
    try:
        target_host_ids = _resolve_host_ids(session, request.host_ids, request.host_ips)

        update_stmt = host_vulnerability.update().where(
            host_vulnerability.c.vulnerability_id == request.plugin_id
        )
        if target_host_ids:
            update_stmt = update_stmt.where(host_vulnerability.c.host_id.in_(target_host_ids))

        # Set both status and closed_date
        result = session.execute(update_stmt.values(
            vuln_status="closed",
            closed_date=datetime.utcnow()
        ))
        session.commit()
        return {"updated": result.rowcount or 0}
    finally:
        session.close()


@router.put("/closed_vulnerabilities/mark")
def update_closed_vulnerabilities(request: UpdateCloseRequest):
    session: Session = SessionLocal()
    try:
        desired_status = request.status.lower()
        if desired_status not in ("closed", "active"):
            return {"error": "Invalid status. Use 'closed' or 'active'"}

        target_host_ids = _resolve_host_ids(session, request.host_ids, request.host_ips)

        update_stmt = host_vulnerability.update().where(
            host_vulnerability.c.vulnerability_id == request.plugin_id
        )
        if target_host_ids:
            update_stmt = update_stmt.where(host_vulnerability.c.host_id.in_(target_host_ids))

        # Set status and closed_date based on the desired status
        if desired_status == "closed":
            result = session.execute(update_stmt.values(
                vuln_status=desired_status,
                closed_date=datetime.utcnow()
            ))
        else:  # active
            result = session.execute(update_stmt.values(
                vuln_status=desired_status,
                closed_date=None
            ))
        
        session.commit()
        return {"updated": result.rowcount or 0}
    finally:
        session.close()

@router.get("/vulnerabilities/{vulnerability_id}/hosts")
def get_vulnerability_hosts(vulnerability_id: int):
    """
    Get all hosts affected by a specific vulnerability for comment context.
    """
    session: Session = SessionLocal()
    try:
        query = text("""
            SELECT 
                h.id as host_id,
                h.hostname,
                h.host_ip,
                h.server_owner,
                hv.plugin_output,
                hv.vuln_status
            FROM hosts h
            INNER JOIN host_vulnerability hv ON h.id = hv.host_id
            WHERE hv.vulnerability_id = :vulnerability_id
            AND hv.vuln_status = 'active'
            ORDER BY h.hostname ASC
        """)
        
        results = session.execute(query, {"vulnerability_id": vulnerability_id}).fetchall()
        
        hosts = []
        for row in results:
            hosts.append({
                "host_id": row.host_id,
                "hostname": row.hostname,
                "host_ip": row.host_ip,
                "server_owner": row.server_owner,
                "plugin_output": row.plugin_output,
                "vuln_status": row.vuln_status
            })
        
        return {"hosts": hosts}
    finally:
        session.close()

@router.get("/vulnerabilities/count_by_severity")
def get_vulnerability_counts():
    session: Session = SessionLocal()
    try:
        # Optimized query to get vulnerability counts by severity in a single query
        severity_counts_query = text("""
            SELECT 
                CASE 
                    WHEN v.severity = 4 THEN 'critical'
                    WHEN v.severity = 3 THEN 'high'
                    WHEN v.severity = 2 THEN 'medium'
                    ELSE 'low'
                END as severity,
                COUNT(DISTINCT v.pluginid) as count
            FROM vulnerabilities v
            WHERE v.severity >= 1
            AND EXISTS (
                SELECT 1 FROM host_vulnerability hv 
                WHERE hv.vulnerability_id = v.pluginid 
                AND hv.vuln_status = 'active'
            )
            GROUP BY 
                CASE 
                    WHEN v.severity = 4 THEN 'critical'
                    WHEN v.severity = 3 THEN 'high'
                    WHEN v.severity = 2 THEN 'medium'
                    ELSE 'low'
                END
        """)
        
        severity_counts_result = session.execute(severity_counts_query).fetchall()
        counts = {row.severity: row.count for row in severity_counts_result}
        
        # Ensure all severity levels are present in response
        expected_severities = ["critical", "high", "medium", "low"]
        for severity in expected_severities:
            if severity not in counts:
                counts[severity] = 0
                
        return counts
    finally:
        session.close()

@router.get("/vulnerabilities/export_csv")
def export_vulnerabilities_csv():
    session: Session = SessionLocal()
    severity_map = {
        1: "low",
        2: "medium",
        3: "high",
        4: "critical"
    }
    def csv_generator():
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "HostName", "Host IP", "Vulnerability Name", "Month of Discovery",  "Severity", 
            "Host Status", "Server Owner", "Application Dependent","Description", "Solution", "Plugin Output", "Last Scan Date"
        ])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)
        query = (
            session.query(
                Host.hostname,
                Host.host_ip,
                Vulnerability.pluginname,
                Vulnerability.month_of_discovery,
                Vulnerability.severity,
                Host.status,
                Host.server_owner,
                Host.application_dependent,
                Vulnerability.description,
                Vulnerability.solution,
                host_vulnerability.c.plugin_output,
                Host.last_scan_date
            )
            .join(host_vulnerability, Vulnerability.pluginid == host_vulnerability.c.vulnerability_id)
            .join(Host, Host.id == host_vulnerability.c.host_id)
            .filter(host_vulnerability.c.vuln_status == "active")
            .filter(Vulnerability.severity >= 1)
        )
        for row in query.yield_per(1000):
            writer.writerow([
                row.hostname,
                row.host_ip,
                row.pluginname,
                row.month_of_discovery,
                severity_map.get(row.severity, "unknown"),
                row.status,
                row.server_owner,
                row.application_dependent,
                row.description,
                row.solution,
                row.plugin_output or "",
                row.last_scan_date.isoformat() if row.last_scan_date else ""
            ])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
        session.close()
    return StreamingResponse(
        csv_generator(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities_hosts.csv"}
    )

@router.get("/vulnerabilities/export_csv_full")
def export_vulnerabilities_csv():
    session: Session = SessionLocal()
    severity_map = {
        1: "low",
        2: "medium",
        3: "high",
        4: "critical"
    }
    def csv_generator():
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "HostName", "Host IP", "Vulnerability Name", "Month of Discovery",  "Severity",
            "Host Status", "Server Owner", "Application Dependent","Description", "Solution", "Plugin Output", "Last Scan Date"
        ])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)
        query = (
            session.query(
                Host.hostname,
                Host.host_ip,
                Vulnerability.pluginname,
                Vulnerability.month_of_discovery,
                Vulnerability.severity,
                Host.status,
                Host.server_owner,
                Host.application_dependent,
                Vulnerability.description,
                Vulnerability.solution,
                host_vulnerability.c.plugin_output,
                Host.last_scan_date
            )
            .join(host_vulnerability, Vulnerability.pluginid == host_vulnerability.c.vulnerability_id)
            .join(Host, Host.id == host_vulnerability.c.host_id)
            .filter(host_vulnerability.c.vuln_status == "active")
            .filter(Vulnerability.severity >= 1)
        )
        for row in query.yield_per(1000):
            writer.writerow([
                row.hostname,
                row.host_ip,
                row.pluginname,
                row.month_of_discovery,
                severity_map.get(row.severity, "unknown"),
                row.status,
                row.server_owner,
                row.application_dependent,
                row.description,
                row.solution,
                row.plugin_output or "",
                row.last_scan_date.isoformat() if row.last_scan_date else ""
            ])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
        session.close()
    return StreamingResponse(
        csv_generator(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities_hosts.csv"}
    )


@router.get("/vulnerabilities/fixed_count")
def count_fixed_vulnerabilities():
    """
    Returns the total number of vulnerability instances (medium, high, critical) that are fixed.
    Counts all vulnerability instances per host, not just unique vulnerabilities.
    """
    session: Session = SessionLocal()
    try:
        # Query to count all vulnerability instances that are fixed (no active hosts)
        # This counts each host-vulnerability combination, not just unique vulnerabilities
        fixed_count_query = text("""
            SELECT COUNT(*) as fixed_count
            FROM host_vulnerability hv
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE v.severity >= 2
            AND hv.vuln_status = 'closed'
        """)
        
        result = session.execute(fixed_count_query).scalar()
        fixed_count = result or 0
        
        return {"fixed_count": fixed_count}
    except Exception as e:
        print(f"Error in count_fixed_vulnerabilities: {e}")
        return {"fixed_count": 0, "error": str(e)}
    finally:
        session.close()

@router.get("/vulnerabilities/fixed_count_public")
def count_fixed_vulnerabilities_public():
    """
    Public version of fixed count endpoint (no authentication required).
    Returns the total number of vulnerability instances (medium, high, critical) that are fixed.
    Counts all vulnerability instances per host, not just unique vulnerabilities.
    """
    session: Session = SessionLocal()
    try:
        # Query to count all vulnerability instances that are fixed (closed status)
        # This counts each host-vulnerability combination, not just unique vulnerabilities
        fixed_count_query = text("""
            SELECT COUNT(*) as fixed_count
            FROM host_vulnerability hv
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE v.severity >= 2
            AND hv.vuln_status = 'closed'
        """)
        
        result = session.execute(fixed_count_query).scalar()
        fixed_count = result or 0
        
        return {"fixed_count": fixed_count}
    except Exception as e:
        print(f"Error in count_fixed_vulnerabilities_public: {e}")
        return {"fixed_count": 0, "error": str(e)}
    finally:
        session.close()

@router.get("/vulnerabilities/fixed_vs_active")
def get_fixed_vs_active_counts():
    """
    Returns detailed counts of fixed vs active vulnerability instances by severity.
    Counts all vulnerability instances per host, not just unique vulnerabilities.
    """
    session: Session = SessionLocal()
    try:
        # Query to get counts by severity and status - counting instances per host
        counts_query = text("""
            SELECT 
                CASE 
                    WHEN v.severity = 4 THEN 'critical'
                    WHEN v.severity = 3 THEN 'high'
                    WHEN v.severity = 2 THEN 'medium'
                    ELSE 'low'
                END as severity,
                hv.vuln_status as status,
                COUNT(*) as count
            FROM host_vulnerability hv
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            WHERE v.severity >= 2
            AND hv.vuln_status IN ('active', 'closed')
            GROUP BY 
                CASE 
                    WHEN v.severity = 4 THEN 'critical'
                    WHEN v.severity = 3 THEN 'high'
                    WHEN v.severity = 2 THEN 'medium'
                    ELSE 'low'
                END,
                hv.vuln_status
            ORDER BY severity DESC, status
        """)
        
        results = session.execute(counts_query).fetchall()
        
        # Organize results
        counts = {}
        for row in results:
            if row.severity not in counts:
                counts[row.severity] = {"active": 0, "fixed": 0}
            if row.status == "closed":
                counts[row.severity]["fixed"] = row.count
            elif row.status == "active":
                counts[row.severity]["active"] = row.count
        
        # Calculate totals
        total_active = sum(counts[sev]["active"] for sev in counts)
        total_fixed = sum(counts[sev]["fixed"] for sev in counts)
        
        return {
            "by_severity": counts,
            "totals": {
                "active": total_active,
                "fixed": total_fixed,
                "total": total_active + total_fixed
            }
        }
    except Exception as e:
        print(f"Error in get_fixed_vs_active_counts: {e}")
        return {"error": str(e)}
    finally:
        session.close()

@router.get("/vulnerabilities/debug")
def debug_vulnerabilities():
    """
    Debug endpoint to check if vulnerabilities exist in the database.
    """
    session: Session = SessionLocal()
    try:
        # Check total vulnerabilities
        total_vulns = session.query(func.count(Vulnerability.pluginid)).scalar()
        
        # Check vulnerabilities by severity
        severity_counts = session.query(
            Vulnerability.severity,
            func.count(Vulnerability.pluginid)
        ).group_by(Vulnerability.severity).all()
        
        # Check host_vulnerability table
        total_host_vuln = session.execute(text("SELECT COUNT(*) FROM host_vulnerability")).scalar()
        active_host_vuln = session.execute(text("SELECT COUNT(*) FROM host_vulnerability WHERE vuln_status = 'active'")).scalar()
        
        # Check active vulnerabilities with severity >= 2
        active_vulns = session.execute(text("""
            SELECT COUNT(DISTINCT v.pluginid) 
            FROM vulnerabilities v 
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id 
            WHERE v.severity >= 2 AND hv.vuln_status = 'active'
        """)).scalar()
        
        return {
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": {str(sev): count for sev, count in severity_counts},
            "total_host_vulnerability_links": total_host_vuln,
            "active_host_vulnerability_links": active_host_vuln,
            "active_vulnerabilities_severity_2_plus": active_vulns
        }
    finally:
        session.close()

@router.get("/vulnerabilities/debug_public")
def debug_vulnerabilities_public():
    """
    Public debug endpoint to check if vulnerabilities exist in the database (no authentication required).
    """
    session: Session = SessionLocal()
    try:
        # Check total vulnerabilities
        total_vulns = session.query(func.count(Vulnerability.pluginid)).scalar()
        
        # Check vulnerabilities by severity
        severity_counts = session.query(
            Vulnerability.severity,
            func.count(Vulnerability.pluginid)
        ).group_by(Vulnerability.severity).all()
        
        # Check host_vulnerability table
        total_host_vuln = session.execute(text("SELECT COUNT(*) FROM host_vulnerability")).scalar()
        active_host_vuln = session.execute(text("SELECT COUNT(*) FROM host_vulnerability WHERE vuln_status = 'active'")).scalar()
        
        # Check active vulnerabilities with severity >= 2
        active_vulns = session.execute(text("""
            SELECT COUNT(DISTINCT v.pluginid) 
            FROM vulnerabilities v 
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id 
            WHERE v.severity >= 2 AND hv.vuln_status = 'active'
        """)).scalar()
        
        return {
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": {str(sev): count for sev, count in severity_counts},
            "total_host_vulnerability_links": total_host_vuln,
            "active_host_vulnerability_links": active_host_vuln,
            "active_vulnerabilities_severity_2_plus": active_vulns
        }
    except Exception as e:
        print(f"Error in debug_vulnerabilities_public: {e}")
        return {"error": str(e)}
    finally:
        session.close()
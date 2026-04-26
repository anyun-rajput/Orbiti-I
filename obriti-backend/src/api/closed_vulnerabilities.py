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
from datetime import datetime, timedelta

router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/closed_vulnerabilities")
def get_closed_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str = Query("", alias="search"),
    severity: str = Query("all", alias="severity"),
    owner: str = Query("all", alias="owner"),
    sort_by: str = Query("closed_date", alias="sort_by"),  # closed_date, hostname, vulnerability_name
    days_since_closed: int = Query(None, ge=1, description="Filter by days since closed")
):
    """
    Get vulnerabilities that have been closed, showing which hosts they were closed on.
    Returns detailed information about closed vulnerabilities with host context and closure dates.
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
                hv.closed_date,
                hv.vuln_status
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

        if days_since_closed:
            base_query += " AND hv.closed_date >= :days_since_closed"
            params["days_since_closed"] = datetime.utcnow() - timedelta(days=days_since_closed)

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
                "closed_date": row.closed_date.isoformat() if row.closed_date else None,
                "vuln_status": row.vuln_status
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

        if days_since_closed:
            count_query += " AND hv.closed_date >= :days_since_closed"
            count_params["days_since_closed"] = datetime.utcnow() - timedelta(days=days_since_closed)

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


@router.get("/closed_vulnerabilities/summary")
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
                COUNT(CASE WHEN v.severity = 1 THEN 1 END) as low_count,
                AVG(TIMESTAMPDIFF(DAY, hv.closed_date, NOW())) as avg_days_since_closed
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
            "avg_days_since_closed": round(result.avg_days_since_closed or 0, 1),
            "severity_breakdown": {
                "critical": result.critical_count or 0,
                "high": result.high_count or 0,
                "medium": result.medium_count or 0,
                "low": result.low_count or 0
            }
        }
    finally:
        session.close()


from concurrent.futures import ThreadPoolExecutor
import asyncio
from collections import defaultdict

@router.get("/closed_vulnerabilities/export_csv")
def export_closed_vulnerabilities_csv():
    """
    Export closed vulnerabilities to CSV format with closure dates.
    High-performance version with batch processing and parallel comment fetching.
    """
    session: Session = SessionLocal()
    
    def csv_generator():
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Vulnerability ID", "Vulnerability Name", "Severity", "CVE", "CVSS Score",
            "Hostname", "Host IP", "Server Owner", "Application Dependent", "OS Name",
            "Closed Date", "Days Since Closed", "Description", "Solution", "Comments"
        ])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        chunk_size = 5000  # Increased chunk size for better performance
        offset = 0
        
        # Pre-fetch all comments in batches for better performance
        def get_comments_batch(vuln_host_pairs):
            if not vuln_host_pairs:
                return {}
            
            # Convert list of tuples to format suitable for IN clause
            vuln_ids = {pair[0] for pair in vuln_host_pairs}
            host_ids = {pair[1] for pair in vuln_host_pairs}
            
            comments_query = """
                SELECT 
                    CASE 
                        WHEN comment_type = 'vulnerability' THEN CONCAT(vulnerability_id, '_0')
                        WHEN comment_type = 'host' THEN CONCAT('0_', host_id)
                        ELSE CONCAT(vulnerability_id, '_', host_id)
                    END as pair_key,
                    CONCAT(
                        '[', comment_type, '] ',
                        content,
                        ' (by ', created_by, ' on ',
                        DATE_FORMAT(created_at, '%Y-%m-%d %H:%i'), ')'
                    ) as comment_text
                FROM comments
                WHERE (comment_type = 'vulnerability' AND vulnerability_id IN :vuln_ids)
                    OR (comment_type = 'host' AND host_id IN :host_ids)
                    OR (comment_type = 'host_vulnerability' 
                        AND host_id IN :host_ids 
                        AND vulnerability_id IN :vuln_ids)
                ORDER BY created_at DESC
            """
            
            comments_result = session.execute(text(comments_query), {
                "vuln_ids": tuple(vuln_ids) if vuln_ids else (0,),
                "host_ids": tuple(host_ids) if host_ids else (0,)
            }).fetchall()
            
            # Group comments by vulnerability-host pair
            comments_dict = defaultdict(list)
            for row in comments_result:
                comments_dict[row.pair_key].append(row.comment_text)
            
            return comments_dict

        while True:
            # Optimized base query with minimal joins and sorting
            base_query = """
                WITH ranked_vulns AS (
                    SELECT DISTINCT
                        vulnerability_id,
                        closed_date
                    FROM host_vulnerability
                    WHERE vuln_status = 'closed'
                    ORDER BY closed_date DESC
                    LIMIT :limit OFFSET :offset
                )
                SELECT 
                    v.pluginid as vulnerability_id,
                    v.pluginname as vulnerability_name,
                    v.severity,
                    v.cpe as cve,
                    v.cvss_base_score,
                    h.id as host_id,
                    h.hostname,
                    h.host_ip,
                    h.server_owner,
                    h.application_dependent,
                    h.os_name,
                    hv.closed_date,
                    v.description,
                    v.solution
                FROM ranked_vulns rv
                INNER JOIN host_vulnerability hv ON hv.vulnerability_id = rv.vulnerability_id 
                    AND hv.closed_date = rv.closed_date
                    AND hv.vuln_status = 'closed'
                INNER JOIN vulnerabilities v ON v.pluginid = hv.vulnerability_id
                INNER JOIN hosts h ON hv.host_id = h.id
                WHERE v.severity >= 1
                ORDER BY hv.closed_date DESC, v.severity DESC, v.pluginname ASC
            """
            
            results = session.execute(text(base_query), {
                "limit": chunk_size,
                "offset": offset
            }).fetchall()
            
            if not results:
                break

            # Prepare vulnerability-host pairs for batch comment fetching
            vuln_host_pairs = [(r.vulnerability_id, r.host_id) for r in results]
            comments_dict = get_comments_batch(vuln_host_pairs)
            
            # Process results with pre-fetched comments
            for row in results:
                vuln_key = f"{row.vulnerability_id}_0"
                host_key = f"0_{row.host_id}"
                pair_key = f"{row.vulnerability_id}_{row.host_id}"
                
                # Combine comments from all relevant keys
                all_comments = []
                all_comments.extend(comments_dict.get(vuln_key, []))
                all_comments.extend(comments_dict.get(host_key, []))
                all_comments.extend(comments_dict.get(pair_key, []))
                
                # Take only the most recent comments if there are too many
                comments = " | ".join(all_comments[:100])
                
                days_since_closed = ""
                if row.closed_date:
                    days_since_closed = (datetime.utcnow() - row.closed_date).days
                
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
                    days_since_closed,
                    (row.description or "").replace('\n', ' ').replace('\r', ' '),
                    (row.solution or "").replace('\n', ' ').replace('\r', ' '),
                    comments
                ])
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)
            
            offset += chunk_size
        
        session.close()

    return StreamingResponse(
        csv_generator(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=closed_vulnerabilities.csv"}
    )


@router.get("/closed_vulnerabilities/check_verification")
def check_vulnerability_verification_status(
    vulnerability_id: int,
    host_id: int
):
    """
    Check if a vulnerability on a specific host has been closed and should not be re-verified.
    Returns verification status and closure information.
    """
    session: Session = SessionLocal()
    try:
        query = """
            SELECT 
                hv.vuln_status,
                hv.closed_date,
                v.pluginname,
                h.hostname,
                h.host_ip
            FROM host_vulnerability hv
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            INNER JOIN hosts h ON hv.host_id = h.id
            WHERE hv.vulnerability_id = :vulnerability_id
            AND hv.host_id = :host_id
        """
        
        result = session.execute(text(query), {
            "vulnerability_id": vulnerability_id,
            "host_id": host_id
        }).first()
        
        if not result:
            return {
                "vulnerability_id": vulnerability_id,
                "host_id": host_id,
                "exists": False,
                "should_verify": True,
                "message": "Vulnerability-host relationship not found"
            }
        
        is_closed = result.vuln_status == "closed"
        should_verify = not is_closed
        
        return {
            "vulnerability_id": vulnerability_id,
            "host_id": host_id,
            "vulnerability_name": result.pluginname,
            "hostname": result.hostname,
            "host_ip": result.host_ip,
            "exists": True,
            "is_closed": is_closed,
            "should_verify": should_verify,
            "closed_date": result.closed_date.isoformat() if result.closed_date else None,
            "message": "Vulnerability is closed and should not be re-verified" if is_closed else "Vulnerability is active and should be verified"
        }
    finally:
        session.close()


@router.get("/closed_vulnerabilities/bulk_check")
def bulk_check_verification_status(
    vulnerability_ids: str = Query(..., description="Comma-separated list of vulnerability IDs"),
    host_ids: str = Query(..., description="Comma-separated list of host IDs")
):
    """
    Bulk check verification status for multiple vulnerability-host combinations.
    """
    session: Session = SessionLocal()
    try:
        vuln_ids = [int(x.strip()) for x in vulnerability_ids.split(",") if x.strip()]
        host_id_list = [int(x.strip()) for x in host_ids.split(",") if x.strip()]
        
        if not vuln_ids or not host_id_list:
            return {"error": "Both vulnerability_ids and host_ids must be provided"}
        
        query = """
            SELECT 
                hv.vulnerability_id,
                hv.host_id,
                hv.vuln_status,
                hv.closed_date,
                v.pluginname,
                h.hostname,
                h.host_ip
            FROM host_vulnerability hv
            INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
            INNER JOIN hosts h ON hv.host_id = h.id
            WHERE hv.vulnerability_id IN :vulnerability_ids
            AND hv.host_id IN :host_ids
        """
        
        results = session.execute(text(query), {
            "vulnerability_ids": tuple(vuln_ids),
            "host_ids": tuple(host_id_list)
        }).fetchall()
        
        verification_status = []
        for row in results:
            is_closed = row.vuln_status == "closed"
            verification_status.append({
                "vulnerability_id": row.vulnerability_id,
                "host_id": row.host_id,
                "vulnerability_name": row.pluginname,
                "hostname": row.hostname,
                "host_ip": row.host_ip,
                "is_closed": is_closed,
                "should_verify": not is_closed,
                "closed_date": row.closed_date.isoformat() if row.closed_date else None
            })
        
        return {
            "verification_status": verification_status,
            "total_checked": len(verification_status),
            "closed_count": sum(1 for item in verification_status if item["is_closed"]),
            "active_count": sum(1 for item in verification_status if not item["is_closed"])
        }
    finally:
        session.close()

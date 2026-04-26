from fastapi import APIRouter, Query, UploadFile, File, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, text
from services.db import SessionLocal
from models.vuln import Host
from models.vuln import Vulnerability  # Import Vulnerability model
from models.vuln import host_vulnerability
import pandas as pd
from io import StringIO
from api.scan import get_current_user, get_current_admin_user
from models.scan import User
from pydantic import BaseModel
from typing import Optional

router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/hosts")
def get_hosts():
    session: Session = SessionLocal()
    try:
        hosts = session.query(Host).all()
        result = []
        for host in hosts:
                    result.append({
            "id": host.id,
            "hostname": host.hostname,
            "host_ip": host.host_ip,
            "last_scan_date": host.last_scan_date.isoformat() if host.last_scan_date else None,
            "status": host.status,
            "server_owner": host.server_owner,
            "os_name": host.os_name or "Unknown",
            "application_dependent": host.application_dependent or "—",
            "ready_for_rescan": host.ready_for_rescan
        })
        return {"hosts": result}
    finally:
        session.close()

@router.get("/hosts_paged")
def get_hosts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str = Query("", alias="search"),
    status: str = Query("all", alias="status"),
    owner: str = Query("all", alias="owner"),
    os_type: str = Query("all", alias="os_type")
):
    session: Session = SessionLocal()
    try:
        query = session.query(Host)

        # Search filter (hostname or host_ip) - using parameterized queries
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    Host.hostname.ilike(search_term),
                    Host.host_ip.ilike(search_term)
                )
            )

        # Status filter
        if status != "all":
            query = query.filter(Host.status == status)

        # Server owner filter
        if owner != "all":
            query = query.filter(Host.server_owner == owner)

        # OS type filter
        if os_type != "all":
            query = query.filter(Host.os_name == os_type)

        total = query.count()
        hosts = (
            query
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )
        result = []
        for host in hosts:
            result.append({
                "id": host.id,
                "hostname": host.hostname,
                "host_ip": host.host_ip,
                "last_scan_date": host.last_scan_date.isoformat() if host.last_scan_date else None,
                "status": host.status,
                "server_owner": host.server_owner,
                "os_name": host.os_name or "Unknown",
                "application_dependent": host.application_dependent or "—",
                "ready_for_rescan": host.ready_for_rescan
            })
        total_pages = (total + page_size - 1) // page_size
        return {
            "hosts": result,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages
        }
    finally:
        session.close()


@router.get("/hosts/by_plugin/{plugin_id}")
def get_hosts_by_plugin(plugin_id: int):
    session: Session = SessionLocal()
    try:
        # Optimized: Single JOIN query
        results = (
            session.query(
                Host.id,
                Host.hostname,
                Host.host_ip,
                Host.last_scan_date,
                Host.status,
                Host.server_owner,
                Host.os_name,
                Host.ready_for_rescan,
                host_vulnerability.c.vuln_status,
                host_vulnerability.c.plugin_output
            )
            .join(host_vulnerability, Host.id == host_vulnerability.c.host_id)
            .filter(host_vulnerability.c.vulnerability_id == plugin_id)
            .all()
        )
        hosts = [
            {
                "id": row.id,
                "hostname": row.hostname,
                "host_ip": row.host_ip,
                "last_scan_date": row.last_scan_date.isoformat() if row.last_scan_date else None,
                "status": row.status,
                "server_owner": row.server_owner,
                "os_name": row.os_name,
                "ready_for_rescan": row.ready_for_rescan,
                "vuln_status": row.vuln_status,
                "plugin_output": row.plugin_output
            }
            for row in results
        ]
        return {"hosts": hosts}
    finally:
        session.close()

@router.post("/hosts/update_from_csv")
async def update_hosts_from_csv(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    session: Session = SessionLocal()
    try:
        content = await file.read()
        df = pd.read_csv(StringIO(content.decode()))
        updated = 0
        for _, row in df.iterrows():
            ip = str(row.get("AssetIPAddress", "")).strip()
            if not ip or ip.lower() == "nan":
                continue
            host = session.query(Host).filter(Host.host_ip == ip).first()
            if host:
                # Update hostname
                host.hostname = row.get("AssetUniqueName", host.hostname)
                # Update server_owner
                app_owner = str(row.get("AssetsApplication/Owner", "")).strip()
                if app_owner.lower() == "decomissioned":
                    host.server_owner = "Decomissioned"
                elif "Owner-" in app_owner:
                    owner = app_owner.split("Owner-")[-1]
                    host.server_owner = owner
                else:
                    host.server_owner = app_owner

                # Update application_dependent
                if "Application:" in app_owner:
                    app_part = app_owner.split("Application:")[-1]
                    app_name = app_part.split(",")[0].strip()
                    host.application_dependent = app_name
                else:
                    host.application_dependent = None

                updated += 1
        session.commit()
        return {"updated_hosts": updated}
    except Exception as e:
        session.rollback()
        return {"error": str(e)}
    finally:
        session.close()


@router.get("/hosts/{host_id}/details")
def get_host_details(host_id: int):
    """Get detailed information about a specific host including vulnerabilities"""
    session: Session = SessionLocal()
    try:
        # Get host information
        host = session.query(Host).filter(Host.id == host_id).first()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        # Get vulnerabilities for this host
        vulnerabilities = (
            session.query(
                Vulnerability.id,
                Vulnerability.pluginname,
                Vulnerability.severity,
                Vulnerability.description,
                Vulnerability.solution,
                Vulnerability.cpe,
                host_vulnerability.c.vuln_status,
                host_vulnerability.c.plugin_output
            )
            .join(host_vulnerability, Vulnerability.pluginid == host_vulnerability.c.vulnerability_id)
            .filter(host_vulnerability.c.host_id == host_id)
            .all()
        )
        
        vuln_list = []
        for vuln in vulnerabilities:
            severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
            vuln_list.append({
                "id": str(vuln.id),
                "name": vuln.pluginname,
                "severity": severity_map.get(vuln.severity, "unknown"),
                "description": vuln.description,
                "solution": vuln.solution,
                "cve": vuln.cpe,
                "vuln_status": vuln.vuln_status,
                "plugin_output": vuln.plugin_output
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
            "ready_for_rescan": host.ready_for_rescan,
            "vulnerabilities": vuln_list
        }
    finally:
        session.close()


@router.get("/hosts/{host_id}/export_csv")
def export_host_vulnerabilities_csv(host_id: int):
    """Export vulnerabilities for a specific host as CSV"""
    session: Session = SessionLocal()
    try:
        # Get host information
        host = session.query(Host).filter(Host.id == host_id).first()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        # Get vulnerabilities with comments for this host using raw SQL
        query = text("""
            SELECT 
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
            FROM vulnerabilities v
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
            LEFT JOIN comments c ON (
                (c.comment_type = 'vulnerability' AND c.vulnerability_id = v.pluginid) OR
                (c.comment_type = 'host' AND c.host_id = :host_id) OR
                (c.comment_type = 'host_vulnerability' AND c.host_id = :host_id AND c.vulnerability_id = v.pluginid)
            )
            WHERE hv.host_id = :host_id
            GROUP BY v.id, v.pluginname, v.severity, v.description, v.solution, 
                     v.cpe, hv.vuln_status, hv.plugin_output
            ORDER BY v.severity DESC, v.pluginname
        """)
        
        results = session.execute(query, {"host_id": host_id}).fetchall()
        
        # Create DataFrame
        data = []
        severity_map = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        
        for result in results:
            data.append({
                "Host": host.hostname,
                "IP Address": host.host_ip,
                "Server Owner": host.server_owner or "Unknown",
                "OS": host.os_name or "Unknown",
                "Application": host.application_dependent or "Not specified",
                "Vulnerability ID": result.id,
                "Vulnerability Name": result.pluginname,
                "Severity": severity_map.get(result.severity, "Unknown"),
                "Description": result.description,
                "Solution": result.solution,
                "CVE": result.cpe or "N/A",
                "Status": result.vuln_status,
                "Plugin Output": result.plugin_output or "N/A",
                "Last Scan": host.last_scan_date.isoformat() if host.last_scan_date else "Never",
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
            headers={"Content-Disposition": f"attachment; filename=host_{host.hostname}_vulnerabilities.csv"}
        )
    finally:
        session.close()


# Pydantic models for request/response
class HostCreate(BaseModel):
    hostname: str
    host_ip: str
    server_owner: Optional[str] = None
    application_dependent: Optional[str] = None
    os_name: str = "Unknown"
    status: str = "active"
    ready_for_rescan: bool = False

class HostUpdate(BaseModel):
    hostname: Optional[str] = None
    host_ip: Optional[str] = None
    server_owner: Optional[str] = None
    application_dependent: Optional[str] = None
    os_name: Optional[str] = None
    status: Optional[str] = None
    ready_for_rescan: Optional[bool] = None

class HostResponse(BaseModel):
    id: int
    hostname: str
    host_ip: str
    last_scan_date: Optional[str] = None
    status: Optional[str] = None
    server_owner: Optional[str] = None
    application_dependent: Optional[str] = None
    os_name: Optional[str] = None
    ready_for_rescan: bool = False

# CRUD endpoints
@router.post("/addhosts", response_model=HostResponse)
def create_host(host_data: HostCreate):
    session: Session = SessionLocal()
    try:
        # Check if host already exists
        existing_host = session.query(Host).filter(
            (Host.hostname == host_data.hostname) | (Host.host_ip == host_data.host_ip)
        ).first()
        
        if existing_host:
            raise HTTPException(status_code=400, detail="Host with this hostname or IP already exists")
        
        new_host = Host(
            hostname=host_data.hostname,
            host_ip=host_data.host_ip,
            server_owner=host_data.server_owner,
            application_dependent=host_data.application_dependent,
            os_name=host_data.os_name,
            status=host_data.status,
            ready_for_rescan=host_data.ready_for_rescan
        )
        
        session.add(new_host)
        session.commit()
        session.refresh(new_host)
        
        return HostResponse(
            id=new_host.id,
            hostname=new_host.hostname,
            host_ip=new_host.host_ip,
            last_scan_date=new_host.last_scan_date.isoformat() if new_host.last_scan_date else None,
            status=new_host.status,
            server_owner=new_host.server_owner,
            application_dependent=new_host.application_dependent,
            os_name=new_host.os_name,
            ready_for_rescan=new_host.ready_for_rescan
        )
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create host: {str(e)}")
    finally:
        session.close()

@router.put("/hosts/{host_id}", response_model=HostResponse)
def update_host(host_id: int, host_data: HostUpdate):
    session: Session = SessionLocal()
    try:
        host = session.query(Host).filter(Host.id == host_id).first()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        # Update only provided fields
        if host_data.hostname is not None:
            host.hostname = host_data.hostname
        if host_data.host_ip is not None:
            host.host_ip = host_data.host_ip
        if host_data.server_owner is not None:
            host.server_owner = host_data.server_owner
        if host_data.application_dependent is not None:
            host.application_dependent = host_data.application_dependent
        if host_data.os_name is not None:
            host.os_name = host_data.os_name
        if host_data.status is not None:
            host.status = host_data.status
        if host_data.ready_for_rescan is not None:
            host.ready_for_rescan = host_data.ready_for_rescan
        
        session.commit()
        session.refresh(host)
        
        return HostResponse(
            id=host.id,
            hostname=host.hostname,
            host_ip=host.host_ip,
            last_scan_date=host.last_scan_date.isoformat() if host.last_scan_date else None,
            status=host.status,
            server_owner=host.server_owner,
            application_dependent=host.application_dependent,
            os_name=host.os_name,
            ready_for_rescan=host.ready_for_rescan
        )
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update host: {str(e)}")
    finally:
        session.close()

@router.delete("/hosts/{host_id}")
def delete_host(host_id: int):
    session: Session = SessionLocal()
    try:
        host = session.query(Host).filter(Host.id == host_id).first()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        session.delete(host)
        session.commit()
        
        return {"message": f"Host {host.hostname} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete host: {str(e)}")
    finally:
        session.close()

@router.delete("/hosts/bulk")
def bulk_delete_hosts(host_ids: list[int]):
    session: Session = SessionLocal()
    try:
        hosts = session.query(Host).filter(Host.id.in_(host_ids)).all()
        if not hosts:
            raise HTTPException(status_code=404, detail="No hosts found with provided IDs")
        
        deleted_count = len(hosts)
        for host in hosts:
            session.delete(host)
        
        session.commit()
        
        return {"message": f"Deleted {deleted_count} hosts successfully", "deleted_count": deleted_count}
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete hosts: {str(e)}")
    finally:
        session.close()

@router.patch("/hosts/{host_id}/toggle-rescan")
def toggle_host_rescan_status(host_id: int, current_admin: User = Depends(get_current_admin_user)):
    """Toggle the ready_for_rescan status of a host"""
    session: Session = SessionLocal()
    try:
        host = session.query(Host).filter(Host.id == host_id).first()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        # Toggle the ready_for_rescan status
        host.ready_for_rescan = not host.ready_for_rescan
        session.commit()
        session.refresh(host)
        
        return {
            "message": f"Host {host.hostname} ready_for_rescan status updated to {host.ready_for_rescan}",
            "host_id": host.id,
            "hostname": host.hostname,
            "ready_for_rescan": host.ready_for_rescan
        }
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to toggle rescan status: {str(e)}")
    finally:
        session.close()

@router.get("/hosts/ready-for-rescan")
def get_hosts_ready_for_rescan(current_admin: User = Depends(get_current_admin_user)):
    """Get all hosts that are ready for immediate rescan"""
    session: Session = SessionLocal()
    try:
        hosts = session.query(Host).filter(Host.ready_for_rescan == True).all()
        result = []
        for host in hosts:
            result.append({
                "id": host.id,
                "hostname": host.hostname,
                "host_ip": host.host_ip,
                "last_scan_date": host.last_scan_date.isoformat() if host.last_scan_date else None,
                "status": host.status,
                "server_owner": host.server_owner,
                "os_name": host.os_name or "Unknown",
                "application_dependent": host.application_dependent or "—",
                "ready_for_rescan": host.ready_for_rescan
            })
        return {"hosts": result, "count": len(result)}
    finally:
        session.close()


@router.post("/hosts/populate-sample-data")
def populate_sample_data():
    """Populate existing hosts with sample OS and application data for testing"""
    session: Session = SessionLocal()
    
    try:
        import random
        
        # Sample OS types
        os_types = ["Linux", "Windows", "macOS", "Unknown"]
        
        # Sample application types
        applications = [
            "Web Server", "Database Server", "File Server", "Mail Server",
            "Application Server", "Development Server", "Test Server",
            "Production Server", "Backup Server", "Monitoring Server"
        ]
        
        # Get all hosts
        hosts = session.query(Host).all()
        
        updated_count = 0
        for host in hosts:
            # Update OS if it's None or empty
            if not host.os_name or host.os_name == "Unknown":
                host.os_name = random.choice(os_types)
                updated_count += 1
            
            # Update application_dependent if it's None or empty
            if not host.application_dependent:
                host.application_dependent = random.choice(applications)
                updated_count += 1
        
        session.commit()
        
        return {
            "message": f"Updated {updated_count} fields across {len(hosts)} hosts",
            "updated_count": updated_count,
            "total_hosts": len(hosts)
        }
        
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to populate sample data: {str(e)}")
    finally:
        session.close()
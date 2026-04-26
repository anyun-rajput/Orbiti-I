from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import text, func, case, exists, select
from services.db import SessionLocal
from models.vuln import Host, Vulnerability, host_vulnerability, VulnerabilityException
from models.daily_summary import DailyVulnerabilitySummary
from services.daily_summary_service import DailySummaryService
from api.scan import get_current_user
import asyncio
from services.nessus_service import fetch_running_scans
from datetime import datetime, timedelta, date
from typing import Optional, List
import functools
import hashlib
import json

router = APIRouter(dependencies=[Depends(get_current_user)])

# Simple in-memory cache for trend data
_trend_cache = {}
_cache_ttl = 300  # 5 minutes TTL

def get_cache_key(days: int, group_by: str) -> str:
    """Generate cache key for trend data"""
    return hashlib.md5(f"trends_{days}_{group_by}".encode()).hexdigest()

def get_cached_trends(cache_key: str) -> Optional[dict]:
    """Get cached trend data if still valid"""
    if cache_key in _trend_cache:
        data, timestamp = _trend_cache[cache_key]
        if datetime.now().timestamp() - timestamp < _cache_ttl:
            return data
        else:
            del _trend_cache[cache_key]
    return None

def cache_trends(cache_key: str, data: dict):
    """Cache trend data with timestamp"""
    _trend_cache[cache_key] = (data, datetime.now().timestamp())

@router.get("/dashboard")
async def get_dashboard_data():
    """
    Optimized dashboard endpoint that returns all dashboard data in a single request.
    This eliminates the need for multiple API calls from the frontend.
    """
    session: Session = SessionLocal()
    try:
        # Get total assets count
        total_assets = session.query(func.count(Host.id)).scalar()
        
        # Get last scan date (most recent scan across all hosts)
        last_scan_query = session.query(func.max(Host.last_scan_date)).scalar()
        last_scan_time = last_scan_query.isoformat() if last_scan_query else None
        
        # Get vulnerability counts by severity excluding exceptions
        # Use the same logic as vulnerability management tab
        from utils.exception_utils import get_vulnerability_count_filter_sql
        
        severity_case = case(
            (Vulnerability.severity == 4, 'critical'),
            (Vulnerability.severity == 3, 'high'),
            (Vulnerability.severity == 2, 'medium'),
            else_='low'
        )
        
        exists_subquery = exists().where(
            host_vulnerability.c.vulnerability_id == Vulnerability.pluginid,
            host_vulnerability.c.vuln_status == 'active'
        )
        
        severity_counts_query = select(
            severity_case.label('severity'),
            func.count(func.distinct(Vulnerability.pluginid)).label('count')
        ).where(
            Vulnerability.severity >= 1,
            exists_subquery,
            text(get_vulnerability_count_filter_sql().lstrip('AND '))
        ).group_by(severity_case)
        
        severity_counts_result = session.execute(severity_counts_query).fetchall()
        vuln_counts = {row.severity: row.count for row in severity_counts_result}
        
        # Get exceptions count
        exceptions_count = session.query(func.count(VulnerabilityException.id)).filter(
            VulnerabilityException.is_active == True
        ).scalar() or 0
        
        # Get top 3 vulnerabilities with host counts (excluding exceptions)
        # Use the same logic as vulnerability management tab
        severity_case = case(
            (Vulnerability.severity == 4, 'critical'),
            (Vulnerability.severity == 3, 'high'),
            (Vulnerability.severity == 2, 'medium'),
            else_='low'
        )
        
        order_case = case(
            (Vulnerability.severity == 4, 3),
            (Vulnerability.severity == 3, 2),
            (Vulnerability.severity == 2, 1),
            else_=0
        )
        
        top_vulns_query = select(
            Vulnerability.pluginid.label('id'),
            Vulnerability.pluginname.label('name'),
            severity_case.label('severity'),
            Vulnerability.description,
            Vulnerability.solution,
            Vulnerability.cpe.label('cve'),
            func.max(host_vulnerability.c.plugin_output).label('plugin_output'),
            func.count(host_vulnerability.c.host_id).label('host_count')
        ).select_from(
            Vulnerability.join(host_vulnerability, Vulnerability.pluginid == host_vulnerability.c.vulnerability_id)
        ).where(
            Vulnerability.severity >= 2,
            host_vulnerability.c.vuln_status == 'active',
            text(get_vulnerability_count_filter_sql().lstrip('AND '))
        ).group_by(
            Vulnerability.pluginid, Vulnerability.pluginname, Vulnerability.severity, 
            Vulnerability.description, Vulnerability.solution, Vulnerability.cpe
        ).order_by(
            order_case.desc(),
            func.count(host_vulnerability.c.host_id).desc()
        ).limit(3)
        
        top_vulns_result = session.execute(top_vulns_query).fetchall()
        top_vulnerabilities = [
            {
                "id": str(row.id),
                "name": row.name,
                "severity": row.severity,
                "hostCount": row.host_count,
                "description": row.description,
                "solution": row.solution,
                "cve": row.cve,
                "plugin_output": row.plugin_output,
                "comment": ""
            }
            for row in top_vulns_result
        ]
        
        # Get running scans asynchronously
        loop = asyncio.get_event_loop()
        running_scans = await loop.run_in_executor(None, fetch_running_scans)
        if running_scans is None:
            running_scans = []
        
        return {
            "total_assets": total_assets,
            "last_scan_time": last_scan_time,
            "vuln_counts": vuln_counts,
            "exceptions_count": exceptions_count,
            "active_scans": running_scans,
            "top_vulnerabilities": top_vulnerabilities
        }
        
    finally:
        session.close()


@router.get("/vulnerability-trends")
async def get_vulnerability_trends(
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    group_by: str = Query("day", description="Group by 'day' or 'month'")
):
    """
    Get vulnerability trends over time grouped by severity.
    Returns daily or monthly counts of total active vulnerabilities at end of day by severity level from the daily summary table.
    Optimized with caching and async processing.
    """
    try:
        # Check cache first
        cache_key = get_cache_key(days, group_by)
        cached_data = get_cached_trends(cache_key)
        if cached_data:
            return cached_data
        
        # Calculate date range
        end_date = date.today()
        start_date = end_date - timedelta(days=days)
        
        # Run database operations in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        summaries = await loop.run_in_executor(
            None, 
            DailySummaryService.ensure_daily_summaries_exist, 
            start_date, 
            end_date
        )
        
        if not summaries:
            result = {
                "trends": [],
                "period": f"{days} days",
                "group_by": group_by,
                "date_range": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat()
                },
                "message": "No data available for the specified period"
            }
            cache_trends(cache_key, result)
            return result
        
        # Process summaries based on grouping
        if group_by == "month":
            # Group by month
            monthly_data = {}
            for summary in summaries:
                month_key = summary.summary_date.strftime("%Y-%m")
                if month_key not in monthly_data:
                    monthly_data[month_key] = {
                        "date": month_key,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "total": 0,
                        "total_hosts_scanned": 0
                    }
                
                monthly_data[month_key]["critical"] += summary.critical_count
                monthly_data[month_key]["high"] += summary.high_count
                monthly_data[month_key]["medium"] += summary.medium_count
                monthly_data[month_key]["low"] += summary.low_count
                monthly_data[month_key]["total"] += summary.total_count
                monthly_data[month_key]["total_hosts_scanned"] += summary.total_hosts_scanned
            
            trends_list = list(monthly_data.values())
        else:
            # Group by day (default)
            trends_list = []
            for summary in summaries:
                trends_list.append({
                    "date": summary.summary_date.strftime("%Y-%m-%d"),
                    "critical": summary.critical_count,
                    "high": summary.high_count,
                    "medium": summary.medium_count,
                    "low": summary.low_count,
                    "total": summary.total_count,
                    "total_hosts_scanned": summary.total_hosts_scanned
                })
        
        # Sort by date
        trends_list.sort(key=lambda x: x["date"])
        
        # Get current date statistics (prefer most recent non-zero data)
        current_date_summary = None
        
        # First, try to find today's data
        for summary in summaries:
            if summary.summary_date == date.today():
                current_date_summary = summary
                break
        
        # If today's data is zero or doesn't exist, get the most recent non-zero data
        if not current_date_summary or (current_date_summary and current_date_summary.total_count == 0):
            # Find the most recent summary with actual data
            for summary in reversed(summaries):  # Start from most recent
                if summary.total_count > 0:
                    current_date_summary = summary
                    break
        
        # Fallback to most recent summary if no non-zero data found
        if not current_date_summary and summaries:
            current_date_summary = summaries[-1]  # Most recent summary
        
        current_stats = {
            "critical": current_date_summary.critical_count if current_date_summary else 0,
            "high": current_date_summary.high_count if current_date_summary else 0,
            "medium": current_date_summary.medium_count if current_date_summary else 0,
            "low": current_date_summary.low_count if current_date_summary else 0,
            "total": current_date_summary.total_count if current_date_summary else 0,
            "total_hosts_scanned": current_date_summary.total_hosts_scanned if current_date_summary else 0,
            "date": current_date_summary.summary_date.isoformat() if current_date_summary else date.today().isoformat()
        }
        
        result = {
            "trends": trends_list,
            "period": f"{days} days",
            "group_by": group_by,
            "date_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "total_summaries": len(summaries),
            "current_stats": current_stats
        }
        
        # Cache the result
        cache_trends(cache_key, result)
        return result
        
    except Exception as e:
        return {
            "error": f"Failed to fetch vulnerability trends: {str(e)}",
            "trends": [],
            "period": f"{days} days",
            "group_by": group_by
        } 
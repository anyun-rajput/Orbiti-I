"""
Service for managing daily vulnerability summary data.
This service calculates and stores daily vulnerability counts for efficient trend analysis.
"""
from sqlalchemy.orm import Session
from sqlalchemy import text, func, and_
from services.db import SessionLocal
from models.vuln import Host, Vulnerability, host_vulnerability
from models.daily_summary import DailyVulnerabilitySummary
from datetime import datetime, date, timedelta
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

class DailySummaryService:
    """Service for managing daily vulnerability summaries"""
    
    @staticmethod
    def get_session() -> Session:
        """Get a database session"""
        return SessionLocal()
    
    @staticmethod
    def calculate_daily_summary(session: Session, target_date: date) -> Optional[DailyVulnerabilitySummary]:
        """
        Calculate vulnerability summary for a specific date.
        Returns the summary object or None if no data found.
        Optimized with better query structure and indexes.
        """
        try:
            # Query to get all active vulnerabilities (matching main dashboard logic)
            # This counts all active vulnerabilities regardless of scan date
            summary_query = text("""
                WITH active_vulns AS (
                    SELECT 
                        v.severity,
                        v.pluginid,
                        h.id as host_id
                    FROM vulnerabilities v
                    INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
                    INNER JOIN hosts h ON hv.host_id = h.id
                    WHERE hv.vuln_status = 'active'
                    AND v.severity >= 1
                )
                SELECT 
                    COUNT(DISTINCT CASE WHEN severity = 4 THEN pluginid END) as critical_count,
                    COUNT(DISTINCT CASE WHEN severity = 3 THEN pluginid END) as high_count,
                    COUNT(DISTINCT CASE WHEN severity = 2 THEN pluginid END) as medium_count,
                    COUNT(DISTINCT CASE WHEN severity = 1 THEN pluginid END) as low_count,
                    COUNT(DISTINCT pluginid) as total_unique_vulnerabilities,
                    COUNT(DISTINCT host_id) as total_hosts_scanned
                FROM active_vulns
            """)
            
            result = session.execute(summary_query, {"target_date": target_date}).fetchone()
            
            if not result:
                logger.warning(f"No data found for date {target_date}")
                return None
            
            # Create or update the daily summary
            existing_summary = session.query(DailyVulnerabilitySummary).filter(
                DailyVulnerabilitySummary.summary_date == target_date
            ).first()
            
            if existing_summary:
                # Update existing record
                existing_summary.critical_count = result.critical_count or 0
                existing_summary.high_count = result.high_count or 0
                existing_summary.medium_count = result.medium_count or 0
                existing_summary.low_count = result.low_count or 0
                existing_summary.total_count = result.total_unique_vulnerabilities or 0
                existing_summary.total_hosts_scanned = result.total_hosts_scanned or 0
                existing_summary.updated_at = datetime.utcnow()
                session.commit()
                # Return a detached copy to avoid session binding issues
                return DailyVulnerabilitySummary(
                    id=existing_summary.id,
                    summary_date=existing_summary.summary_date,
                    critical_count=existing_summary.critical_count,
                    high_count=existing_summary.high_count,
                    medium_count=existing_summary.medium_count,
                    low_count=existing_summary.low_count,
                    total_count=existing_summary.total_count,
                    total_hosts_scanned=existing_summary.total_hosts_scanned,
                    created_at=existing_summary.created_at,
                    updated_at=existing_summary.updated_at
                )
            else:
                # Create new record
                total_count = result.total_unique_vulnerabilities or 0
                
                new_summary = DailyVulnerabilitySummary(
                    summary_date=target_date,
                    critical_count=result.critical_count or 0,
                    high_count=result.high_count or 0,
                    medium_count=result.medium_count or 0,
                    low_count=result.low_count or 0,
                    total_count=total_count,
                    total_hosts_scanned=result.total_hosts_scanned or 0
                )
                session.add(new_summary)
                session.commit()
                # Return a detached copy to avoid session binding issues
                return DailyVulnerabilitySummary(
                    id=new_summary.id,
                    summary_date=new_summary.summary_date,
                    critical_count=new_summary.critical_count,
                    high_count=new_summary.high_count,
                    medium_count=new_summary.medium_count,
                    low_count=new_summary.low_count,
                    total_count=new_summary.total_count,
                    total_hosts_scanned=new_summary.total_hosts_scanned,
                    created_at=new_summary.created_at,
                    updated_at=new_summary.updated_at
                )
                
        except Exception as e:
            logger.error(f"Error calculating daily summary for {target_date}: {e}")
            session.rollback()
            return None
    
    @staticmethod
    def calculate_summary_for_date_range(start_date: date, end_date: date) -> List[DailyVulnerabilitySummary]:
        """
        Calculate daily summaries for a range of dates.
        Returns list of summary objects.
        """
        session = SessionLocal()
        summaries = []
        
        try:
            current_date = start_date
            while current_date <= end_date:
                summary = DailySummaryService.calculate_daily_summary(session, current_date)
                if summary:
                    summaries.append(summary)
                current_date += timedelta(days=1)
            
            return summaries
        finally:
            session.close()
    
    @staticmethod
    def get_daily_summaries(start_date: date, end_date: date) -> List[DailyVulnerabilitySummary]:
        """
        Get existing daily summaries for a date range.
        Returns list of summary objects.
        """
        session = SessionLocal()
        try:
            summaries = session.query(DailyVulnerabilitySummary).filter(
                and_(
                    DailyVulnerabilitySummary.summary_date >= start_date,
                    DailyVulnerabilitySummary.summary_date <= end_date
                )
            ).order_by(DailyVulnerabilitySummary.summary_date.asc()).all()
            
            return summaries
        finally:
            session.close()
    
    @staticmethod
    def ensure_daily_summaries_exist(start_date: date, end_date: date) -> List[DailyVulnerabilitySummary]:
        """
        Ensure daily summaries exist for a date range.
        Calculates missing summaries and returns all summaries for the range.
        Optimized version using batch queries.
        """
        session = SessionLocal()
        summaries = []
        
        try:
            # Get all existing summaries for the date range in one query
            existing_summaries = session.query(DailyVulnerabilitySummary).filter(
                and_(
                    DailyVulnerabilitySummary.summary_date >= start_date,
                    DailyVulnerabilitySummary.summary_date <= end_date
                )
            ).all()
            
            # Create a set of existing dates for fast lookup
            existing_dates = {summary.summary_date for summary in existing_summaries}
            summaries.extend(existing_summaries)
            
            # Find missing dates
            missing_dates = []
            current_date = start_date
            while current_date <= end_date:
                if current_date not in existing_dates:
                    missing_dates.append(current_date)
                current_date += timedelta(days=1)
            
            # Batch calculate missing summaries
            if missing_dates:
                missing_summaries = DailySummaryService._batch_calculate_summaries(session, missing_dates)
                summaries.extend(missing_summaries)
            
            # Sort by date
            summaries.sort(key=lambda x: x.summary_date)
            
            return summaries
        finally:
            session.close()
    
    @staticmethod
    def _batch_calculate_summaries(session: Session, missing_dates: List[date]) -> List[DailyVulnerabilitySummary]:
        """
        Batch calculate summaries for multiple dates efficiently.
        """
        summaries = []
        
        # Group dates by month for more efficient queries
        dates_by_month = {}
        for date_obj in missing_dates:
            month_key = date_obj.strftime("%Y-%m")
            if month_key not in dates_by_month:
                dates_by_month[month_key] = []
            dates_by_month[month_key].append(date_obj)
        
        for month_key, month_dates in dates_by_month.items():
            # Calculate summaries for this month
            month_summaries = DailySummaryService._calculate_month_summaries(session, month_dates)
            summaries.extend(month_summaries)
        
        return summaries
    
    @staticmethod
    def _calculate_month_summaries(session: Session, dates: List[date]) -> List[DailyVulnerabilitySummary]:
        """
        Calculate summaries for all dates in a month using optimized batch query.
        """
        if not dates:
            return []
        
        summaries = []
        min_date = min(dates)
        max_date = max(dates)
        
        # Query to get total vulnerabilities at end of each day for the date range
        batch_query = text("""
            WITH date_series AS (
                SELECT DATE_ADD(:min_date, INTERVAL seq.seq DAY) as target_date
                FROM (
                    SELECT 0 as seq UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION
                    SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9 UNION
                    SELECT 10 UNION SELECT 11 UNION SELECT 12 UNION SELECT 13 UNION SELECT 14 UNION
                    SELECT 15 UNION SELECT 16 UNION SELECT 17 UNION SELECT 18 UNION SELECT 19 UNION
                    SELECT 20 UNION SELECT 21 UNION SELECT 22 UNION SELECT 23 UNION SELECT 24 UNION
                    SELECT 25 UNION SELECT 26 UNION SELECT 27 UNION SELECT 28 UNION SELECT 29 UNION
                    SELECT 30 UNION SELECT 31 UNION SELECT 32 UNION SELECT 33 UNION SELECT 34 UNION
                    SELECT 35 UNION SELECT 36 UNION SELECT 37 UNION SELECT 38 UNION SELECT 39 UNION
                    SELECT 40 UNION SELECT 41 UNION SELECT 42 UNION SELECT 43 UNION SELECT 44 UNION
                    SELECT 45 UNION SELECT 46 UNION SELECT 47 UNION SELECT 48 UNION SELECT 49 UNION
                    SELECT 50 UNION SELECT 51 UNION SELECT 52 UNION SELECT 53 UNION SELECT 54 UNION
                    SELECT 55 UNION SELECT 56 UNION SELECT 57 UNION SELECT 58 UNION SELECT 59 UNION
                    SELECT 60 UNION SELECT 61 UNION SELECT 62 UNION SELECT 63 UNION SELECT 64 UNION
                    SELECT 65 UNION SELECT 66 UNION SELECT 67 UNION SELECT 68 UNION SELECT 69 UNION
                    SELECT 70 UNION SELECT 71 UNION SELECT 72 UNION SELECT 73 UNION SELECT 74 UNION
                    SELECT 75 UNION SELECT 76 UNION SELECT 77 UNION SELECT 78 UNION SELECT 79 UNION
                    SELECT 80 UNION SELECT 81 UNION SELECT 82 UNION SELECT 83 UNION SELECT 84 UNION
                    SELECT 85 UNION SELECT 86 UNION SELECT 87 UNION SELECT 88 UNION SELECT 89 UNION
                    SELECT 90 UNION SELECT 91 UNION SELECT 92 UNION SELECT 93 UNION SELECT 94 UNION
                    SELECT 95 UNION SELECT 96 UNION SELECT 97 UNION SELECT 98 UNION SELECT 99
                ) seq
                WHERE DATE_ADD(:min_date, INTERVAL seq.seq DAY) <= :max_date
            ),
            end_of_day_vulns AS (
                SELECT 
                    ds.target_date,
                    v.severity,
                    v.pluginid,
                    h.id as host_id
                FROM date_series ds
                CROSS JOIN hosts h
                INNER JOIN host_vulnerability hv ON h.id = hv.host_id
                INNER JOIN vulnerabilities v ON hv.vulnerability_id = v.pluginid
                WHERE DATE(h.last_scan_date) <= ds.target_date
                AND hv.vuln_status = 'active'
                AND v.severity >= 1
            )
            SELECT 
                target_date as scan_date,
                COUNT(DISTINCT CASE WHEN severity = 4 THEN pluginid END) as critical_count,
                COUNT(DISTINCT CASE WHEN severity = 3 THEN pluginid END) as high_count,
                COUNT(DISTINCT CASE WHEN severity = 2 THEN pluginid END) as medium_count,
                COUNT(DISTINCT CASE WHEN severity = 1 THEN pluginid END) as low_count,
                COUNT(DISTINCT pluginid) as total_unique_vulnerabilities,
                COUNT(DISTINCT host_id) as total_hosts_scanned
            FROM end_of_day_vulns
            GROUP BY target_date
        """)
        
        try:
            results = session.execute(batch_query, {
                "min_date": min_date,
                "max_date": max_date
            }).fetchall()
            
            # Create a lookup for results by date
            results_by_date = {row.scan_date: row for row in results}
            
            # Create summaries for all requested dates
            for target_date in dates:
                if target_date in results_by_date:
                    result = results_by_date[target_date]
                    total_count = result.total_unique_vulnerabilities or 0
                    
                    summary = DailyVulnerabilitySummary(
                        summary_date=target_date,
                        critical_count=result.critical_count or 0,
                        high_count=result.high_count or 0,
                        medium_count=result.medium_count or 0,
                        low_count=result.low_count or 0,
                        total_count=total_count,
                        total_hosts_scanned=result.total_hosts_scanned or 0
                    )
                else:
                    # Create empty summary for dates with no data
                    summary = DailyVulnerabilitySummary(
                        summary_date=target_date,
                        critical_count=0,
                        high_count=0,
                        medium_count=0,
                        low_count=0,
                        total_count=0,
                        total_hosts_scanned=0
                    )
                
                session.add(summary)
                summaries.append(summary)
            
            session.commit()
            return summaries
            
        except Exception as e:
            logger.error(f"Error in batch calculation for dates {min_date} to {max_date}: {e}")
            session.rollback()
            return []
    
    @staticmethod
    def get_latest_summary_date() -> Optional[date]:
        """Get the date of the most recent daily summary"""
        session = SessionLocal()
        try:
            latest = session.query(func.max(DailyVulnerabilitySummary.summary_date)).scalar()
            return latest
        finally:
            session.close()
    
    @staticmethod
    def get_earliest_summary_date() -> Optional[date]:
        """Get the date of the earliest daily summary"""
        session = SessionLocal()
        try:
            earliest = session.query(func.min(DailyVulnerabilitySummary.summary_date)).scalar()
            return earliest
        finally:
            session.close()
    
    @staticmethod
    def backfill_historical_data(days_back: int = 30) -> int:
        """
        Backfill historical data for the specified number of days.
        Returns the number of summaries created/updated.
        """
        end_date = date.today()
        start_date = end_date - timedelta(days=days_back)
        
        logger.info(f"Backfilling daily summaries from {start_date} to {end_date}")
        
        summaries = DailySummaryService.calculate_summary_for_date_range(start_date, end_date)
        logger.info(f"Created/updated {len(summaries)} daily summaries")
        
        return len(summaries)
    
    @staticmethod
    def cleanup_old_summaries(days_to_keep: int = 365) -> int:
        """
        Clean up old daily summaries, keeping only the specified number of days.
        Returns the number of summaries deleted.
        """
        cutoff_date = date.today() - timedelta(days=days_to_keep)
        
        session = SessionLocal()
        try:
            deleted_count = session.query(DailyVulnerabilitySummary).filter(
                DailyVulnerabilitySummary.summary_date < cutoff_date
            ).delete()
            
            session.commit()
            logger.info(f"Deleted {deleted_count} old daily summaries")
            return deleted_count
        finally:
            session.close()

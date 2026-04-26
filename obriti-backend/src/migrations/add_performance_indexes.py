#!/usr/bin/env python3
"""
Migration script to add performance indexes for vulnerability trends API.
This script adds indexes to improve query performance for the daily summary system.
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from services.db import SessionLocal, engine
from sqlalchemy import text
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def add_performance_indexes():
    """Add performance indexes for better query performance"""
    session = SessionLocal()
    try:
        logger.info("🚀 Adding performance indexes for vulnerability trends API...")
        
        # Indexes for hosts table
        indexes_to_create = [
            # Index on last_scan_date for efficient date filtering
            "CREATE INDEX IF NOT EXISTS idx_hosts_last_scan_date ON hosts(last_scan_date)",
            
            # Index on host_vulnerability table for efficient joins
            "CREATE INDEX IF NOT EXISTS idx_host_vuln_host_id ON host_vulnerability(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_host_vuln_vuln_id ON host_vulnerability(vulnerability_id)",
            "CREATE INDEX IF NOT EXISTS idx_host_vuln_status ON host_vulnerability(vuln_status)",
            "CREATE INDEX IF NOT EXISTS idx_host_vuln_composite ON host_vulnerability(host_id, vulnerability_id, vuln_status)",
            
            # Index on vulnerabilities table for severity filtering
            "CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_pluginid ON vulnerabilities(pluginid)",
            
            # Composite index for the main query pattern
            "CREATE INDEX IF NOT EXISTS idx_vuln_severity_pluginid ON vulnerabilities(severity, pluginid)",
            
            # Index on daily summary table for range queries
            "CREATE INDEX IF NOT EXISTS idx_daily_summary_date_range ON daily_vulnerability_summary(summary_date)",
            
            # Additional indexes for common query patterns
            "CREATE INDEX IF NOT EXISTS idx_hosts_scan_date_severity ON hosts(last_scan_date) WHERE last_scan_date IS NOT NULL",
        ]
        
        created_count = 0
        for index_sql in indexes_to_create:
            try:
                session.execute(text(index_sql))
                created_count += 1
                logger.info(f"✅ Created index: {index_sql.split('ON')[1].split('(')[0].strip()}")
            except Exception as e:
                logger.warning(f"⚠️ Index might already exist or failed: {e}")
        
        session.commit()
        logger.info(f"🎉 Successfully created {created_count} performance indexes!")
        
        # Verify indexes were created
        verify_indexes(session)
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error creating indexes: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def verify_indexes(session):
    """Verify that the indexes were created successfully"""
    try:
        # Check indexes on hosts table
        hosts_indexes = session.execute(text("""
            SELECT name FROM sqlite_master 
            WHERE type='index' AND tbl_name='hosts' 
            AND name LIKE 'idx_%'
        """)).fetchall()
        
        # Check indexes on host_vulnerability table
        hv_indexes = session.execute(text("""
            SELECT name FROM sqlite_master 
            WHERE type='index' AND tbl_name='host_vulnerability' 
            AND name LIKE 'idx_%'
        """)).fetchall()
        
        # Check indexes on vulnerabilities table
        vuln_indexes = session.execute(text("""
            SELECT name FROM sqlite_master 
            WHERE type='index' AND tbl_name='vulnerabilities' 
            AND name LIKE 'idx_%'
        """)).fetchall()
        
        # Check indexes on daily_vulnerability_summary table
        daily_indexes = session.execute(text("""
            SELECT name FROM sqlite_master 
            WHERE type='index' AND tbl_name='daily_vulnerability_summary' 
            AND name LIKE 'idx_%'
        """)).fetchall()
        
        logger.info(f"📊 Index verification:")
        logger.info(f"   Hosts table: {len(hosts_indexes)} indexes")
        logger.info(f"   Host_vulnerability table: {len(hv_indexes)} indexes")
        logger.info(f"   Vulnerabilities table: {len(vuln_indexes)} indexes")
        logger.info(f"   Daily summary table: {len(daily_indexes)} indexes")
        
        total_indexes = len(hosts_indexes) + len(hv_indexes) + len(vuln_indexes) + len(daily_indexes)
        logger.info(f"   Total performance indexes: {total_indexes}")
        
    except Exception as e:
        logger.warning(f"Could not verify indexes: {e}")

def drop_performance_indexes():
    """Drop performance indexes (for testing/rollback)"""
    session = SessionLocal()
    try:
        logger.info("🗑️ Dropping performance indexes...")
        
        indexes_to_drop = [
            "DROP INDEX IF EXISTS idx_hosts_last_scan_date",
            "DROP INDEX IF EXISTS idx_host_vuln_host_id",
            "DROP INDEX IF EXISTS idx_host_vuln_vuln_id",
            "DROP INDEX IF EXISTS idx_host_vuln_status",
            "DROP INDEX IF EXISTS idx_host_vuln_composite",
            "DROP INDEX IF EXISTS idx_vuln_severity",
            "DROP INDEX IF EXISTS idx_vuln_pluginid",
            "DROP INDEX IF EXISTS idx_vuln_severity_pluginid",
            "DROP INDEX IF EXISTS idx_daily_summary_date_range",
            "DROP INDEX IF EXISTS idx_hosts_scan_date_severity",
        ]
        
        for index_sql in indexes_to_drop:
            try:
                session.execute(text(index_sql))
                logger.info(f"✅ Dropped index: {index_sql.split('IF EXISTS')[1].strip()}")
            except Exception as e:
                logger.warning(f"⚠️ Could not drop index: {e}")
        
        session.commit()
        logger.info("🎉 Performance indexes dropped successfully!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error dropping indexes: {e}")
        session.rollback()
        return False
    finally:
        session.close()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Manage performance indexes for vulnerability trends API")
    parser.add_argument("--add", action="store_true", help="Add performance indexes")
    parser.add_argument("--drop", action="store_true", help="Drop performance indexes")
    parser.add_argument("--verify", action="store_true", help="Verify existing indexes")
    
    args = parser.parse_args()
    
    if args.add:
        success = add_performance_indexes()
        sys.exit(0 if success else 1)
    elif args.drop:
        success = drop_performance_indexes()
        sys.exit(0 if success else 1)
    elif args.verify:
        session = SessionLocal()
        try:
            verify_indexes(session)
        finally:
            session.close()
    else:
        print("Please specify --add, --drop, or --verify")
        sys.exit(1)

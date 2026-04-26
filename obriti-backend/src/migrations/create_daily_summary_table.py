#!/usr/bin/env python3
"""
Migration script to create the daily_vulnerability_summary table.
Run this script to set up the daily summary table for trend analysis.
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from sqlalchemy import create_engine, text
from services.db import get_database_url
from models.daily_summary import Base
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_daily_summary_table():
    """Create the daily_vulnerability_summary table"""
    try:
        # Create engine
        engine = create_engine(get_database_url())
        
        # Create the table
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Daily vulnerability summary table created successfully")
        
        # Verify table creation
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT COUNT(*) as table_exists 
                FROM information_schema.tables 
                WHERE table_name = 'daily_vulnerability_summary'
            """))
            
            if result.fetchone()[0] > 0:
                logger.info("✅ Table verification successful")
            else:
                logger.error("❌ Table creation failed")
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error creating daily summary table: {e}")
        return False

def drop_daily_summary_table():
    """Drop the daily_vulnerability_summary table (for testing/cleanup)"""
    try:
        engine = create_engine(get_database_url())
        
        with engine.connect() as conn:
            conn.execute(text("DROP TABLE IF EXISTS daily_vulnerability_summary"))
            conn.commit()
        
        logger.info("✅ Daily vulnerability summary table dropped")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error dropping daily summary table: {e}")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Manage daily vulnerability summary table")
    parser.add_argument("--action", choices=["create", "drop"], default="create", 
                       help="Action to perform: create or drop table")
    
    args = parser.parse_args()
    
    if args.action == "create":
        success = create_daily_summary_table()
        if success:
            print("Migration completed successfully!")
        else:
            print("Migration failed!")
            sys.exit(1)
    elif args.action == "drop":
        success = drop_daily_summary_table()
        if success:
            print("Table dropped successfully!")
        else:
            print("Failed to drop table!")
            sys.exit(1)

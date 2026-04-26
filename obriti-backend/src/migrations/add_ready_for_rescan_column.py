#!/usr/bin/env python3
"""
Migration script to add ready_for_rescan column to hosts table.
This script adds a boolean column to track which hosts are ready for immediate rescan.
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from services.db import SessionLocal, engine
from sqlalchemy import text
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def add_ready_for_rescan_column():
    """Add ready_for_rescan column to hosts table"""
    session = SessionLocal()
    try:
        logger.info("🚀 Adding ready_for_rescan column to hosts table...")
        
        # Check if column already exists
        check_column_query = text(
            """
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'hosts'
              AND column_name = 'ready_for_rescan'
            """
        )
        exists = session.execute(check_column_query).scalar()
        
        if exists == 0:
            # Add the column
            add_column_query = text(
                "ALTER TABLE hosts ADD COLUMN ready_for_rescan BOOLEAN DEFAULT FALSE NOT NULL"
            )
            session.execute(add_column_query)
            session.commit()
            logger.info("✅ Successfully added ready_for_rescan column to hosts table")
        else:
            logger.info("ℹ️ ready_for_rescan column already exists in hosts table")
            
    except Exception as e:
        session.rollback()
        logger.error(f"❌ Error adding ready_for_rescan column: {e}")
        raise
    finally:
        session.close()

def downgrade():
    """Remove ready_for_rescan column from hosts table"""
    session = SessionLocal()
    try:
        logger.info("🔄 Removing ready_for_rescan column from hosts table...")
        
        # Check if column exists
        check_column_query = text(
            """
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'hosts'
              AND column_name = 'ready_for_rescan'
            """
        )
        exists = session.execute(check_column_query).scalar()
        
        if exists > 0:
            # Remove the column
            drop_column_query = text(
                "ALTER TABLE hosts DROP COLUMN ready_for_rescan"
            )
            session.execute(drop_column_query)
            session.commit()
            logger.info("✅ Successfully removed ready_for_rescan column from hosts table")
        else:
            logger.info("ℹ️ ready_for_rescan column does not exist in hosts table")
            
    except Exception as e:
        session.rollback()
        logger.error(f"❌ Error removing ready_for_rescan column: {e}")
        raise
    finally:
        session.close()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "downgrade":
        downgrade()
    else:
        add_ready_for_rescan_column()

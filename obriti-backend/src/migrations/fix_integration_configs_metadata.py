"""
Database migration script to rename metadata column to extra_metadata in integration_configs table
"""

from sqlalchemy import create_engine, text
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration - load from environment variable
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable must be set to run this migration")

def update_integration_configs_table():
    """Update integration_configs table to rename metadata column to extra_metadata"""
    
    engine = create_engine(DATABASE_URL)
    
    try:
        with engine.connect() as connection:
            # Check if the old metadata column exists
            result = connection.execute(text("""
                SELECT COUNT(*) as count 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'integration_configs' 
                AND COLUMN_NAME = 'metadata'
            """))
            
            if result.fetchone()[0] > 0:
                print("Renaming metadata column to extra_metadata...")
                # Rename the column using ALTER TABLE
                connection.execute(text("""
                    ALTER TABLE integration_configs 
                    CHANGE COLUMN metadata extra_metadata TEXT NULL
                """))
                connection.commit()
                print("Successfully renamed metadata column to extra_metadata")
            else:
                print("Column metadata does not exist or already renamed")
                
            # Check if extra_metadata column exists now
            result = connection.execute(text("""
                SELECT COUNT(*) as count 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'integration_configs' 
                AND COLUMN_NAME = 'extra_metadata'
            """))
            
            if result.fetchone()[0] > 0:
                print("extra_metadata column exists in integration_configs table")
            else:
                print("Creating extra_metadata column...")
                connection.execute(text("""
                    ALTER TABLE integration_configs 
                    ADD COLUMN extra_metadata TEXT NULL
                """))
                connection.commit()
                print("Successfully created extra_metadata column")
                
    except Exception as e:
        print(f"Error updating integration_configs table: {e}")
        raise

if __name__ == "__main__":
    update_integration_configs_table()

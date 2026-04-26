"""
Database migration script to create integration_configs table
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration - load from environment variable
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable must be set to run this migration")

def create_integration_configs_table():
    """Create integration_configs table for storing Microsoft SSO and Nessus configurations"""
    
    engine = create_engine(DATABASE_URL)
    
    try:
        with engine.connect() as connection:
            print("Creating integration_configs table...")
            
            # Check if table already exists
            result = connection.execute(text("""
                SELECT COUNT(*) as count FROM INFORMATION_SCHEMA.TABLES 
                WHERE TABLE_NAME = 'integration_configs'
            """))
            
            if result.fetchone()[0] == 0:
                print("Creating integration_configs table...")
                connection.execute(text("""
                    CREATE TABLE integration_configs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        integration_type VARCHAR(50) NOT NULL,
                        enabled BOOLEAN DEFAULT FALSE,
                        config_data TEXT NULL,
                        status VARCHAR(50) DEFAULT 'not_configured',
                        last_tested DATETIME NULL,
                        last_sync DATETIME NULL,
                        metadata TEXT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        created_by INT NOT NULL,
                        FOREIGN KEY (created_by) REFERENCES users(id),
                        UNIQUE KEY unique_integration_type (integration_type)
                    )
                """))
                connection.commit()
                print("✓ integration_configs table created successfully")
            else:
                print("integration_configs table already exists")
            
            print("\n✅ Integration configs table migration completed successfully!")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        raise

if __name__ == "__main__":
    create_integration_configs_table()

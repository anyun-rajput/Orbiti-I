"""
Service to initialize integration_configs table on startup
"""

from sqlalchemy import create_engine, text
from config.database import DATABASE_URL
import logging

logger = logging.getLogger(__name__)

def create_integration_configs_table():
    """Create integration_configs table if it doesn't exist"""
    try:
        engine = create_engine(DATABASE_URL)
        
        with engine.connect() as connection:
            # Check if table exists
            result = connection.execute(text("""
                SELECT COUNT(*) as count FROM INFORMATION_SCHEMA.TABLES 
                WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'integration_configs'
            """))
            
            if result.fetchone()[0] == 0:
                logger.info("Creating integration_configs table...")
                
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
                logger.info("✓ integration_configs table created successfully")
            else:
                logger.info("integration_configs table already exists")
                
    except Exception as e:
        logger.error(f"Failed to create integration_configs table: {e}")
        # Don't raise exception to prevent startup failure
        pass

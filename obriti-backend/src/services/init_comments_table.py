from sqlalchemy import create_engine, text
import logging
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def create_comments_table():
    """Create the comments table if it doesn't exist"""
    try:
        from models.vuln import Base
        from models.comments import Comment
        DATABASE_URL = os.getenv("DATABASE_URL")
        if not DATABASE_URL:
            raise ValueError("DATABASE_URL environment variable must be set")
        engine = create_engine(DATABASE_URL)
        
        # Create all tables using SQLAlchemy
        Base.metadata.create_all(bind=engine)
        print("Comments table created successfully using SQLAlchemy")
        
    except Exception as e:
        print(f"Error creating comments table: {e}")
        logging.error(f"Error creating comments table: {e}")
        
        # Fallback to manual SQL creation
        try:
            DATABASE_URL = os.getenv("DATABASE_URL")
            if not DATABASE_URL:
                raise ValueError("DATABASE_URL environment variable must be set")
            engine = create_engine(DATABASE_URL)
            
            # Create comments table manually
            create_table_sql = """
            CREATE TABLE IF NOT EXISTS comments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                comment_type ENUM('vulnerability', 'host', 'host_vulnerability') NOT NULL,
                content TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                created_by VARCHAR(255) NOT NULL,
                vulnerability_id INT NULL,
                host_id INT NULL,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(pluginid) ON DELETE CASCADE,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                INDEX idx_comment_type (comment_type),
                INDEX idx_vulnerability_id (vulnerability_id),
                INDEX idx_host_id (host_id),
                INDEX idx_created_by (created_by)
            );
            """
            
            with engine.connect() as connection:
                connection.execute(text(create_table_sql))
                connection.commit()
                
            print("Comments table created successfully using manual SQL")
            
        except Exception as e2:
            print(f"Error creating comments table with fallback: {e2}")
            logging.error(f"Error creating comments table with fallback: {e2}")

if __name__ == "__main__":
    create_comments_table()

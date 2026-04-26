from sqlalchemy import create_engine
from models.scan import Base as ScanBase
from models.vuln import Base as VulnBase
from models.scan import BatchScan
from models.vuln import Host, Vulnerability
from services.db import engine
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add this to create all tables, including users
if __name__ == "__main__":
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL environment variable must be set to create tables")
    engine = create_engine(database_url)
    
    # Create all tables from both models
    ScanBase.metadata.create_all(engine)
    VulnBase.metadata.create_all(engine)
    
    print("All database tables created successfully!")
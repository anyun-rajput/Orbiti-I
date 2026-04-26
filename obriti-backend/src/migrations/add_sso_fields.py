"""
Database migration script to add Microsoft SSO fields to existing users table.
Run this script after updating the User model to add auth_provider and external_id fields.
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

def migrate_add_sso_fields():
    """Add SSO fields to users table and set default values for existing users"""
    
    engine = create_engine(DATABASE_URL)
    
    try:
        with engine.connect() as connection:
            # Check if columns already exist
            result = connection.execute(text("""
                SELECT COUNT(*) as count FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'auth_provider'
            """))
            
            if result.fetchone()[0] == 0:
                print("Adding auth_provider column...")
                connection.execute(text("""
                    ALTER TABLE users 
                    ADD COLUMN auth_provider VARCHAR(50) DEFAULT 'local'
                """))
                connection.commit()
                print("✓ auth_provider column added")
            else:
                print("auth_provider column already exists")
            
            # Check if external_id column exists
            result = connection.execute(text("""
                SELECT COUNT(*) as count FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'external_id'
            """))
            
            if result.fetchone()[0] == 0:
                print("Adding external_id column...")
                connection.execute(text("""
                    ALTER TABLE users 
                    ADD COLUMN external_id VARCHAR(255) NULL
                """))
                connection.commit()
                print("✓ external_id column added")
            else:
                print("external_id column already exists")
            
            # Update existing users to have 'local' auth_provider if NULL
            print("Updating existing users with default auth_provider...")
            result = connection.execute(text("""
                UPDATE users 
                SET auth_provider = 'local' 
                WHERE auth_provider IS NULL
            """))
            connection.commit()
            print(f"✓ Updated {result.rowcount} users with default auth_provider")
            
            # Make hashed_password nullable for SSO users
            print("Making hashed_password nullable...")
            connection.execute(text("""
                ALTER TABLE users 
                MODIFY COLUMN hashed_password VARCHAR(255) NULL
            """))
            connection.commit()
            print("✓ hashed_password column is now nullable")
            
            print("\n✅ Migration completed successfully!")
            print("All existing users have been set to 'local' authentication.")
            print("New Microsoft SSO users will be created with 'microsoft' auth_provider.")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        raise

if __name__ == "__main__":
    print("Starting Microsoft SSO migration...")
    print("This will add auth_provider and external_id fields to the users table.")
    
    confirm = input("Do you want to proceed? (y/N): ")
    if confirm.lower() == 'y':
        migrate_add_sso_fields()
    else:
        print("Migration cancelled.")

from sqlalchemy import text
from services.db import SessionLocal

def add_plugin_output_column():
    """
    Add plugin_output column to the vulnerabilities table if it doesn't exist.
    """
    session = SessionLocal()
    try:
        # Check if the column already exists
        check_column_query = text("""
            SELECT COUNT(*) 
            FROM information_schema.columns 
            WHERE table_schema = 'nessusdb' 
            AND table_name = 'vulnerabilities' 
            AND column_name = 'plugin_output'
        """)
        
        column_exists = session.execute(check_column_query).scalar()
        
        if column_exists == 0:
            # Add the plugin_output column
            add_column_query = text("""
                ALTER TABLE vulnerabilities 
                ADD COLUMN plugin_output TEXT NULL
            """)
            
            session.execute(add_column_query)
            session.commit()
            print("✅ Successfully added plugin_output column to vulnerabilities table")
        else:
            print("ℹ️ plugin_output column already exists in vulnerabilities table")
            
    except Exception as e:
        session.rollback()
        print(f"❌ Error adding plugin_output column: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    add_plugin_output_column() 
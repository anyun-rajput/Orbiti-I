from sqlalchemy import text, inspect
from services.db import SessionLocal, engine

def index_exists(table_name, index_name):
    """Check if an index exists in the database."""
    inspector = inspect(engine)
    indexes = inspector.get_indexes(table_name)
    return any(index['name'] == index_name for index in indexes)

def optimize_database():
    """
    Add database indexes to improve query performance for dashboard and vulnerability queries.
    This version is MySQL compatible.
    """
    session = SessionLocal()
    try:
        # Define indexes with their respective tables
        indexes = [
            # Format: (index_name, table_name, column_definition)
            ("idx_vulnerabilities_severity", "vulnerabilities", "(severity)"),
            ("idx_host_vulnerability_vuln_id", "host_vulnerability", "(vulnerability_id)"),
            ("idx_host_vulnerability_host_id", "host_vulnerability", "(host_id)"),
            ("idx_host_vulnerability_status", "host_vulnerability", "(vuln_status)"),
            ("idx_hosts_last_scan_date", "hosts", "(last_scan_date)"),
            ("idx_vulnerabilities_pluginname", "vulnerabilities", "(pluginname)"),
            ("idx_vulnerabilities_cpe", "vulnerabilities", "(cpe)"),
        ]
        
        # Special case for conditional index
        conditional_index = ("idx_vuln_severity_active", "vulnerabilities", "(severity)", "WHERE severity >= 2")
        
        # Create regular indexes
        for index_name, table_name, columns in indexes:
            try:
                if not index_exists(table_name, index_name):
                    create_sql = f"CREATE INDEX {index_name} ON {table_name} {columns}"
                    session.execute(text(create_sql))
                    print(f"Created index: {create_sql}")
                else:
                    print(f"Index {index_name} already exists on table {table_name}")
            except Exception as e:
                print(f"Error creating index {index_name}: {e}")
        
        # Handle the conditional index separately
        try:
            index_name, table_name, columns, condition = conditional_index
            if not index_exists(table_name, index_name):
                create_sql = f"CREATE INDEX {index_name} ON {table_name} {columns} {condition}"
                session.execute(text(create_sql))
                print(f"Created index: {create_sql}")
            else:
                print(f"Index {index_name} already exists on table {table_name}")
        except Exception as e:
            print(f"Error creating conditional index: {e}")
        
        session.commit()
        print("Database optimization completed successfully!")
        
    except Exception as e:
        session.rollback()
        print(f"Error optimizing database: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    optimize_database()
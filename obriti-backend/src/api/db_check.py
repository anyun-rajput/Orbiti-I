from sqlalchemy import text
from services.db import SessionLocal

def check_database():
    """Check database connection and table structure"""
    session = SessionLocal()
    try:
        print("🔍 Checking database connection...")
        
        # Check if tables exist
        tables_query = text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        """)
        tables = session.execute(tables_query).fetchall()
        print(f"Found tables: {[t[0] for t in tables]}")
        
        # Check vulnerabilities table
        vuln_count = session.execute(text("SELECT COUNT(*) FROM vulnerabilities")).scalar()
        print(f"Total vulnerabilities: {vuln_count}")
        
        # Check host_vulnerability table
        hv_count = session.execute(text("SELECT COUNT(*) FROM host_vulnerability")).scalar()
        print(f"Total host_vulnerability links: {hv_count}")
        
        # Check active vulnerabilities
        active_vulns = session.execute(text("""
            SELECT COUNT(DISTINCT v.pluginid) 
            FROM vulnerabilities v 
            INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id 
            WHERE v.severity >= 2 AND hv.vuln_status = 'active'
        """)).scalar()
        print(f"Active vulnerabilities (severity >= 2): {active_vulns}")
        
        # Check severity distribution
        severity_dist = session.execute(text("""
            SELECT severity, COUNT(*) 
            FROM vulnerabilities 
            WHERE severity >= 2 
            GROUP BY severity
        """)).fetchall()
        print(f"Severity distribution: {severity_dist}")
        
        return True
        
    except Exception as e:
        print(f"❌ Database check failed: {e}")
        return False
    finally:
        session.close()

if __name__ == "__main__":
    check_database() 
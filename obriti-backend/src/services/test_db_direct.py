#!/usr/bin/env python3
"""
Direct database test to check if the vulnerability data exists and queries work.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from services.db import SessionLocal
from sqlalchemy import text

def test_database_directly():
    """Test database queries directly"""
    session = SessionLocal()
    try:
        print("🔍 Testing database directly...")
        
        # Test 1: Check if tables exist
        print("\n1. Checking tables...")
        try:
            tables = session.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")).fetchall()
            print(f"Tables found: {[t[0] for t in tables]}")
        except Exception as e:
            print(f"❌ Error checking tables: {e}")
            return False
        
        # Test 2: Check vulnerabilities table
        print("\n2. Checking vulnerabilities table...")
        try:
            vuln_count = session.execute(text("SELECT COUNT(*) FROM vulnerabilities")).scalar()
            print(f"Total vulnerabilities: {vuln_count}")
        except Exception as e:
            print(f"❌ Error checking vulnerabilities: {e}")
            return False
        
        # Test 3: Check host_vulnerability table
        print("\n3. Checking host_vulnerability table...")
        try:
            hv_count = session.execute(text("SELECT COUNT(*) FROM host_vulnerability")).scalar()
            print(f"Total host_vulnerability links: {hv_count}")
        except Exception as e:
            print(f"❌ Error checking host_vulnerability: {e}")
            return False
        
        # Test 4: Check active vulnerabilities
        print("\n4. Checking active vulnerabilities...")
        try:
            active_vulns = session.execute(text("""
                SELECT COUNT(DISTINCT v.pluginid) 
                FROM vulnerabilities v 
                INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id 
                WHERE v.severity >= 2 AND hv.vuln_status = 'active'
            """)).scalar()
            print(f"Active vulnerabilities (severity >= 2): {active_vulns}")
        except Exception as e:
            print(f"❌ Error checking active vulnerabilities: {e}")
            return False
        
        # Test 5: Try the actual query
        print("\n5. Testing the actual vulnerability query...")
        try:
            query = """
                SELECT 
                    v.pluginid as id,
                    v.pluginname as name,
                    v.severity,
                    v.description,
                    v.solution,
                    v.cpe as cve,
                    COUNT(hv.host_id) as host_count
                FROM vulnerabilities v
                INNER JOIN host_vulnerability hv ON v.pluginid = hv.vulnerability_id
                WHERE v.severity >= 2
                AND hv.vuln_status = 'active'
                GROUP BY v.pluginid, v.pluginname, v.severity, v.description, v.solution, v.cpe
                ORDER BY 
                    CASE v.severity
                        WHEN 4 THEN 3
                        WHEN 3 THEN 2
                        WHEN 2 THEN 1
                        ELSE 0
                    END DESC,
                    COUNT(hv.host_id) DESC
                LIMIT 5
            """
            results = session.execute(text(query)).fetchall()
            print(f"Query returned {len(results)} results")
            if results:
                print("First result:")
                row = results[0]
                print(f"  ID: {row.id}")
                print(f"  Name: {row.name}")
                print(f"  Severity: {row.severity}")
                print(f"  Host Count: {row.host_count}")
        except Exception as e:
            print(f"❌ Error executing vulnerability query: {e}")
            return False
        
        print("\n✅ All database tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False
    finally:
        session.close()

if __name__ == "__main__":
    test_database_directly() 
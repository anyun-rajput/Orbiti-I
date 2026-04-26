from sqlalchemy import create_engine, update, and_, insert, text
from sqlalchemy.orm import sessionmaker
from models.vuln import Base, Host, Vulnerability, host_vulnerability  # <-- add host_vulnerability import
from models.comments import Comment  # Import Comment model
from datetime import datetime
import re
import os
from collections import defaultdict
import asyncio
import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
import threading
from functools import partial

# Configuration for parallel processing
import os
import psutil

# Get system resources for optimal configuration
CPU_COUNT = psutil.cpu_count(logical=True)
MEMORY_GB = psutil.virtual_memory().total / (1024**3)

# Configuration based on system resources
PARALLEL_CONFIG = {
    'max_workers': min(CPU_COUNT, 4),  # Reduced from 8 to 4 to prevent database locks
    'chunk_size': max(200, 1000 // CPU_COUNT),  # Larger chunks to reduce concurrent operations
    'max_concurrent': min(CPU_COUNT // 2, 2),  # Reduced from 4 to 2
    'memory_threshold_gb': 4.0,  # Memory threshold for large datasets
}

def get_optimal_processing_method(data_size: int) -> str:
    """
    Automatically select the best processing method based on data size and system resources
    """
    if data_size < 1000:
        return "standard"
    elif data_size < 5000:
        return "fast"
    else:
        # Use fast processing for large datasets
        return "fast"

def store_scan_results_simple(scan_json, isinventoryscan: bool = False):
    """
    Simple sequential processing to avoid database lock issues
    """
    scan_details = scan_json.get("scan_details", []) if isinstance(scan_json, dict) else scan_json
    
    print(f"Using simple sequential processing for {len(scan_details)} items")
    
    # Process in smaller chunks to avoid memory issues
    chunk_size = 500
    total_processed = 0
    
    for i in range(0, len(scan_details), chunk_size):
        chunk = scan_details[i:i + chunk_size]
        chunk_json = {"scan_details": chunk}
        
        print(f"Processing chunk {i//chunk_size + 1}/{(len(scan_details) + chunk_size - 1)//chunk_size}")
        
        # Use the regular optimized function for each chunk
        store_scan_results(chunk_json, isinventoryscan)
        total_processed += len(chunk)
    
    # Handle inventory scan logic after all chunks are processed
    if isinventoryscan:
        print("📋 Processing inventory scan logic for offline hosts...")
        session = SessionLocal()
        try:
            # Get all unique host IPs from the scan
            unique_host_ips = set()
            for detail in scan_details:
                host_ip = detail.get("Host")
                if host_ip:
                    unique_host_ips.add(host_ip)
            
            # Mark all hosts found in this scan as online
            hosts_marked_online = 0
            hosts_created = 0
            for host_ip in unique_host_ips:
                # Check if host exists
                current_host = session.query(Host).filter(Host.host_ip == host_ip).first()
                if current_host:
                    # Existing host - update status
                    if current_host.status != "online":
                        hosts_marked_online += 1
                        print(f"🔄 Marking host {host_ip} as online (was {current_host.status})")
                    else:
                        print(f"ℹ️  Host {host_ip} already online")
                    
                    session.execute(
                        Host.__table__.update()
                        .where(Host.host_ip == host_ip)
                        .values(status="online")
                    )
                else:
                    # New host - create it
                    print(f"➕ Creating new host {host_ip} as online")
                    new_host = Host(
                        hostname=host_ip,
                        host_ip=host_ip,
                        last_scan_date=None,
                        status="online",
                        server_owner=None,
                        os_name="Unknown"
                    )
                    session.add(new_host)
                    hosts_created += 1
            
            # Only mark hosts as offline if they were previously online and are not in this scan
            all_existing_hosts = session.query(Host).all()
            hosts_in_scan = set(unique_host_ips)
            
            hosts_marked_offline = 0
            vulnerabilities_closed = 0
            
            for host in all_existing_hosts:
                if host.host_ip not in hosts_in_scan and host.status == "online":
                    # Host was online but not found in scan - mark as offline
                    session.execute(
                        Host.__table__.update()
                        .where(Host.id == host.id)
                        .values(status="offline")
                    )
                    hosts_marked_offline += 1
                    
                    # Count and close active vulnerabilities associated with this offline host
                    vuln_count = session.execute(
                        host_vulnerability.select()
                        .where(host_vulnerability.c.host_id == host.id)
                        .where(host_vulnerability.c.vuln_status == "active")
                    ).rowcount
                    
                    if vuln_count > 0:
                        session.execute(
                            host_vulnerability.update()
                            .where(host_vulnerability.c.host_id == host.id)
                            .where(host_vulnerability.c.vuln_status == "active")
                            .values(vuln_status="closed", closed_date=datetime.utcnow())
                        )
                        vulnerabilities_closed += vuln_count
                        print(f"🔒 Marked host {host.host_ip} as offline and closed {vuln_count} vulnerabilities")
                    else:
                        print(f"🔒 Marked host {host.host_ip} as offline (no active vulnerabilities to close)")
                elif host.host_ip not in hosts_in_scan and host.status != "online":
                    print(f"ℹ️  Host {host.host_ip} was already {host.status}, no action needed")
            
            session.commit()
            print(f"✅ Inventory scan processing completed.")
            print(f"📊 Inventory scan summary:")
            print(f"   - Hosts in scan: {len(hosts_in_scan)}")
            print(f"   - New hosts created: {hosts_created}")
            print(f"   - Hosts marked online: {hosts_marked_online}")
            print(f"   - Hosts marked offline: {hosts_marked_offline}")
            print(f"   - Vulnerabilities closed: {vulnerabilities_closed}")
            
        except Exception as e:
            session.rollback()
            print(f"❌ Error in inventory scan processing: {e}")
            raise
        finally:
            session.close()
    
    print(f"Simple processing completed. Total items processed: {total_processed}")

def store_scan_results_fast(scan_json, isinventoryscan: bool = False):
    """
    Ultra-fast processing using bulk operations and optimized strategies
    """
    import time
    start_time = time.time()
    
    session = SessionLocal()
    try:
        scan_details = scan_json.get("scan_details", []) if isinstance(scan_json, dict) else scan_json
        
        print(f"🚀 Fast processing {len(scan_details):,} items")
        print(f"⏰ Started at: {time.strftime('%H:%M:%S')}")
        
        # Pre-process all data in memory first
        host_os_info = {}
        host_vulns_in_scan = defaultdict(set)
        host_plugin_output = {}
        vulnerabilities_to_create = []
        hosts_to_create = []
        host_vuln_links_to_create = []
        
        # Get all unique host IPs and plugin IDs
        unique_host_ips = set()
        unique_plugin_ids = set()
        
        print("📊 Step 1/6: Pre-processing data...")
        step_start = time.time()
        
        # First pass: collect all data
        for i, detail in enumerate(scan_details):
            if i % 1000 == 0 and i > 0:
                progress = (i / len(scan_details)) * 100
                elapsed = time.time() - step_start
                print(f"   📈 Progress: {progress:.1f}% ({i:,}/{len(scan_details):,}) - {elapsed:.1f}s elapsed")
            
            host_ip = detail.get("Host")
            plugin_id = detail.get("Plugin ID")
            
            if host_ip:
                unique_host_ips.add(host_ip)
            
            if plugin_id:
                unique_plugin_ids.add(plugin_id)
            
            # Extract OS information
            if str(plugin_id) == "11936" and detail.get("Plugin Output"):
                os_name = extract_os_from_plugin_output(detail.get("Plugin Output"))
                host_os_info[host_ip] = os_name

        step_time = time.time() - step_start
        print(f"✅ Step 1 completed in {step_time:.1f}s")
        print(f"📈 Found {len(unique_host_ips)} unique hosts and {len(unique_plugin_ids)} unique vulnerabilities")

        # Batch query existing data
        print("🔍 Step 2/6: Querying existing data...")
        step_start = time.time()
        
        existing_hosts = {
            host.host_ip: host 
            for host in session.query(Host).filter(Host.host_ip.in_(unique_host_ips)).all()
        }
        
        existing_vulns = {
            vuln.pluginid: vuln 
            for vuln in session.query(Vulnerability).filter(Vulnerability.pluginid.in_(unique_plugin_ids)).all()
        }

        step_time = time.time() - step_start
        print(f"✅ Step 2 completed in {step_time:.1f}s")
        print(f"📊 Found {len(existing_hosts)} existing hosts and {len(existing_vulns)} existing vulnerabilities")
        print(f"🔍 Existing vulnerabilities plugin IDs: {list(existing_vulns.keys())}")

        # Process all vulnerabilities in memory
        print("⚡ Step 3/6: Processing vulnerabilities...")
        step_start = time.time()
        
        processed_count = 0
        vulnerabilities_to_create_ids = set()  # Track which plugin_ids we're adding
        for i, detail in enumerate(scan_details):
            if i % 1000 == 0 and i > 0:
                progress = (i / len(scan_details)) * 100
                elapsed = time.time() - step_start
                print(f"   📈 Progress: {progress:.1f}% ({i:,}/{len(scan_details):,}) - {elapsed:.1f}s elapsed")
            
            host_ip = detail.get("Host")
            plugin_id = detail.get("Plugin ID")
            plugin_name = detail.get("Name")
            plugin_output = detail.get("Plugin Output")
            
            # Track all hosts that were scanned, regardless of vulnerability severity
            # This ensures we can close old vulnerabilities even if host only has low/no severity vulns
            if host_ip:
                # Initialize the set for this host if it doesn't exist
                if host_ip not in host_vulns_in_scan:
                    host_vulns_in_scan[host_ip] = set()
            
            severity = risk_string_to_int(detail.get("Risk"))
            if severity is None or severity < 2:
                continue

            processed_count += 1
            host_vulns_in_scan[host_ip].add(plugin_id)
            if host_ip and plugin_id is not None:
                host_plugin_output[(host_ip, plugin_id)] = plugin_output

            # Prepare host data
            if host_ip not in existing_hosts:
                os_name = host_os_info.get(host_ip, "Unknown")
                hosts_to_create.append({
                    'hostname': host_ip,
                    'host_ip': host_ip,
                    'last_scan_date': None,
                    'status': 'online',
                    'server_owner': None,
                    'os_name': os_name
                })

            # Prepare vulnerability data
            if plugin_id not in existing_vulns and plugin_id not in vulnerabilities_to_create_ids:
                month_str = datetime.now().strftime("%Y-%m")
                vulnerabilities_to_create.append({
                    'pluginid': plugin_id,
                    'pluginfamily': None,
                    'pluginname': plugin_name,
                    'severity': severity,
                    'description': detail.get("Description"),
                    'solution': detail.get("Solution"),
                    'synopsis': detail.get("Synopsis"),
                    'cpe': detail.get("CVE"),
                    'cvss_base_score': None,
                    'month_of_discovery': month_str
                })
                vulnerabilities_to_create_ids.add(plugin_id)  # Track that we've added this plugin_id
                print(f"➕ Adding vulnerability {plugin_id} to creation list")
            elif plugin_id in existing_vulns:
                print(f"✅ Vulnerability {plugin_id} already exists in database")
            elif plugin_id in vulnerabilities_to_create_ids:
                print(f"🔄 Vulnerability {plugin_id} already queued for creation")

        step_time = time.time() - step_start
        print(f"✅ Step 3 completed in {step_time:.1f}s")
        print(f"📦 Prepared {len(hosts_to_create)} hosts and {len(vulnerabilities_to_create)} vulnerabilities for creation")
        print(f"🎯 Processed {processed_count} valid vulnerabilities (filtered out low/none severity)")

        # Bulk operations with optimized strategy
        print("💾 Step 4/6: Executing bulk operations...")
        step_start = time.time()
        
        # 1. Bulk insert hosts
        if hosts_to_create:
            print(f"📥 Bulk inserting {len(hosts_to_create)} hosts...")
            host_insert_start = time.time()
            session.execute(Host.__table__.insert(), hosts_to_create)
            session.commit()
            host_insert_time = time.time() - host_insert_start
            print(f"✅ Hosts inserted successfully in {host_insert_time:.1f}s")

        # 2. Bulk insert vulnerabilities  
        if vulnerabilities_to_create:
            print(f"📥 Bulk inserting {len(vulnerabilities_to_create)} vulnerabilities...")
            print(f"🔍 Plugin IDs to insert: {[v['pluginid'] for v in vulnerabilities_to_create]}")
            
            # Double-check that we're not trying to insert existing vulnerabilities
            plugin_ids_to_insert = [v['pluginid'] for v in vulnerabilities_to_create]
            existing_plugin_ids = list(existing_vulns.keys())
            duplicates = [pid for pid in plugin_ids_to_insert if pid in existing_plugin_ids]
            if duplicates:
                print(f"⚠️  WARNING: Found {len(duplicates)} plugin IDs that already exist in database: {duplicates}")
                # Remove duplicates from vulnerabilities_to_create
                vulnerabilities_to_create = [v for v in vulnerabilities_to_create if v['pluginid'] not in existing_plugin_ids]
                print(f"🔄 Removed duplicates, now inserting {len(vulnerabilities_to_create)} vulnerabilities")
            
            vuln_insert_start = time.time()
            session.execute(Vulnerability.__table__.insert(), vulnerabilities_to_create)
            session.commit()
            vuln_insert_time = time.time() - vuln_insert_start
            print(f"✅ Vulnerabilities inserted successfully in {vuln_insert_time:.1f}s")

        step_time = time.time() - step_start
        print(f"✅ Step 4 completed in {step_time:.1f}s")

        # 3. Update existing hosts
        print("🔄 Step 5/6: Updating existing records...")
        step_start = time.time()
        
        # Update hosts in bulk
        if existing_hosts:
            host_updates = []
            for host in existing_hosts.values():
                host.status = "online"
                if not isinventoryscan:
                    host.last_scan_date = datetime.now()
                    print(f"🔄 Updated last_scan_date for host {host.host_ip} to {host.last_scan_date}")
                if host.host_ip in host_os_info:
                    host.os_name = host_os_info[host.host_ip]
                host_updates.append(host)
            
            if host_updates:
                print(f"🔄 Updating {len(host_updates)} existing hosts...")
                update_start = time.time()
                session.add_all(host_updates)
                session.commit()
                update_time = time.time() - update_start
                print(f"✅ Hosts updated successfully in {update_time:.1f}s")

        # No Vulnerability.plugin_output updates (moved to association table)

        step_time = time.time() - step_start
        print(f"✅ Step 5 completed in {step_time:.1f}s")

        # 4. Handle host-vulnerability relationships efficiently
        # Skip vulnerability processing for inventory scans - we only want to track host availability
        if not isinventoryscan:
            print("🔗 Step 6/6: Processing host-vulnerability relationships...")
            step_start = time.time()

            # Get all host IDs for relationship processing
            print("🔍 Getting host IDs for relationships...")
            all_hosts = session.query(Host).filter(Host.host_ip.in_(unique_host_ips)).all()
            host_id_map = {host.host_ip: host.id for host in all_hosts}
            host_ids = set(host_id_map.values())
            print(f"📊 Found {len(host_id_map)} hosts for relationship processing")

            # OPTIMIZATION: Get ALL existing relationships in one bulk query
            print("🔗 Loading existing host-vulnerability relationships...")
            bulk_query_start = time.time()
            existing_relationships = session.execute(
                host_vulnerability.select().where(host_vulnerability.c.host_id.in_(host_ids))
            ).fetchall()
            bulk_query_time = time.time() - bulk_query_start
            print(f"✅ Loaded {len(existing_relationships)} existing relationships in {bulk_query_time:.1f}s")

            # Create efficient lookup structures
            existing_links = {}  # (host_id, vuln_id) -> relationship data
            for link in existing_relationships:
                key = (link.host_id, link.vulnerability_id)
                existing_links[key] = link

            # Prepare bulk operations
            relationships_to_update = []
            relationships_to_create = []
            total_relationships = 0

            print("🔗 Analyzing relationships...")
            analysis_start = time.time()

            # Process all relationships efficiently
            for host_ip, plugin_ids_in_scan in host_vulns_in_scan.items():
                if host_ip not in host_id_map:
                    continue

                host_id = host_id_map[host_ip]
                total_relationships += len(plugin_ids_in_scan)

                for plugin_id in plugin_ids_in_scan:
                    key = (host_id, plugin_id)
                    plugin_output = host_plugin_output.get((host_ip, plugin_id))

                    if key in existing_links:
                        # Relationship exists - update if needed
                        existing_link = existing_links[key]
                        if existing_link.vuln_status != 'active' or existing_link.plugin_output != plugin_output:
                            relationships_to_update.append({
                                'host_id': host_id,
                                'vulnerability_id': plugin_id,
                                'plugin_output': plugin_output
                            })
                    else:
                        # New relationship - create
                        relationships_to_create.append({
                            'host_id': host_id,
                            'vulnerability_id': plugin_id,
                            'vuln_status': 'active',
                            'plugin_output': plugin_output
                        })

            analysis_time = time.time() - analysis_start
            print(f"✅ Analyzed {total_relationships} relationships in {analysis_time:.1f}s")
            print(f"📊 To create: {len(relationships_to_create)}, To update: {len(relationships_to_update)}")

            # Bulk create new relationships
            if relationships_to_create:
                print(f"📥 Bulk creating {len(relationships_to_create)} new relationships...")
                create_start = time.time()
                session.execute(host_vulnerability.insert(), relationships_to_create)
                create_time = time.time() - create_start
                print(f"✅ Created relationships in {create_time:.1f}s")

            # Bulk update existing relationships
            if relationships_to_update:
                print(f"🔄 Bulk updating {len(relationships_to_update)} existing relationships...")
                update_start = time.time()
                for update_data in relationships_to_update:
                    session.execute(
                        host_vulnerability.update()
                        .where(
                            (host_vulnerability.c.host_id == update_data['host_id']) &
                            (host_vulnerability.c.vulnerability_id == update_data['vulnerability_id'])
                        )
                        .values(
                            vuln_status="active",
                            plugin_output=update_data['plugin_output']
                        )
                    )
                update_time = time.time() - update_start
                print(f"✅ Updated relationships in {update_time:.1f}s")

            session.commit()

            step_time = time.time() - step_start
            print(f"✅ Step 6 completed in {step_time:.1f}s")
        else:
            print("ℹ️  Skipping vulnerability processing for inventory scan - only tracking host availability")

        # 5. Close old relationships efficiently
        # Skip this for inventory scans - we only want to track host availability, not vulnerability changes
        if not isinventoryscan:
            print("🔒 Closing old relationships...")
            close_start = time.time()

            # OPTIMIZATION: Collect all active vulnerabilities in current scan
            all_current_vulns = set()
            for plugin_ids in host_vulns_in_scan.values():
                all_current_vulns.update(plugin_ids)

            print(f"📊 Found {len(all_current_vulns)} unique vulnerabilities in current scan")

            # Bulk close all relationships that are not in the current scan
            # This is much more efficient than individual queries per host
            close_query = host_vulnerability.update().where(
                (host_vulnerability.c.host_id.in_(host_ids)) &
                (host_vulnerability.c.vulnerability_id.notin_(all_current_vulns)) &
                (host_vulnerability.c.vuln_status == "active")
            ).values(vuln_status="closed", closed_date=datetime.utcnow())

            closed_count = session.execute(close_query).rowcount
            session.commit()

            close_time = time.time() - close_start
            print(f"✅ Closed {closed_count} old relationships in {close_time:.1f}s")
        else:
            print("ℹ️  Skipping vulnerability closure for inventory scan - only tracking host availability")

        # Handle inventory scan logic
        if isinventoryscan:
            print("📋 Processing inventory scan logic...")
            inventory_start = time.time()
            
            # Create host_id_map for inventory scan processing
            all_hosts = session.query(Host).filter(Host.host_ip.in_(unique_host_ips)).all()
            host_id_map = {host.host_ip: host.id for host in all_hosts}
            print(f"📊 Found {len(host_id_map)} hosts for inventory processing")
            
            # Mark all hosts found in this scan as online
            hosts_marked_online = 0
            hosts_created = 0
            for host_ip in unique_host_ips:
                if host_ip in host_id_map:
                    # Existing host - mark as online
                    host_id = host_id_map[host_ip]
                    # Check current status before updating
                    current_host = session.query(Host).filter(Host.id == host_id).first()
                    if current_host and current_host.status != "online":
                        hosts_marked_online += 1
                        print(f"🔄 Marking host {host_ip} as online (was {current_host.status})")
                    elif current_host and current_host.status == "online":
                        print(f"ℹ️  Host {host_ip} already online")
                    
                    session.execute(
                        Host.__table__.update()
                        .where(Host.id == host_id)
                        .values(status="online")
                    )
                else:
                    # New host - create it
                    print(f"➕ Creating new host {host_ip} as online")
                    new_host = Host(
                        hostname=host_ip,
                        host_ip=host_ip,
                        last_scan_date=None,
                        status="online",
                        server_owner=None,
                        os_name="Unknown"
                    )
                    session.add(new_host)
                    hosts_created += 1
            
            # Only mark hosts as offline if they were previously online and are not in this scan
            all_existing_hosts = session.query(Host).all()
            hosts_in_scan = set(unique_host_ips)
            
            hosts_marked_offline = 0
            vulnerabilities_closed = 0
            
            for host in all_existing_hosts:
                if host.host_ip not in hosts_in_scan and host.status == "online":
                    # Host was online but not found in scan - mark as offline
                    session.execute(
                        Host.__table__.update()
                        .where(Host.id == host.id)
                        .values(status="offline")
                    )
                    hosts_marked_offline += 1
                    
                    # Count and close active vulnerabilities associated with this offline host
                    vuln_count = session.execute(
                        host_vulnerability.select()
                        .where(host_vulnerability.c.host_id == host.id)
                        .where(host_vulnerability.c.vuln_status == "active")
                    ).rowcount
                    
                    if vuln_count > 0:
                        session.execute(
                            host_vulnerability.update()
                            .where(host_vulnerability.c.host_id == host.id)
                            .where(host_vulnerability.c.vuln_status == "active")
                            .values(vuln_status="closed", closed_date=datetime.utcnow())
                        )
                        vulnerabilities_closed += vuln_count
                        print(f"🔒 Marked host {host.host_ip} as offline and closed {vuln_count} vulnerabilities")
                    else:
                        print(f"🔒 Marked host {host.host_ip} as offline (no active vulnerabilities to close)")
                elif host.host_ip not in hosts_in_scan and host.status != "online":
                    print(f"ℹ️  Host {host.host_ip} was already {host.status}, no action needed")
            
            inventory_time = time.time() - inventory_start
            print(f"✅ Inventory scan processing completed in {inventory_time:.1f}s")
            print(f"📊 Inventory scan summary:")
            print(f"   - Hosts in scan: {len(hosts_in_scan)}")
            print(f"   - New hosts created: {hosts_created}")
            print(f"   - Hosts marked online: {hosts_marked_online}")
            print(f"   - Hosts marked offline: {hosts_marked_offline}")
            print(f"   - Vulnerabilities closed: {vulnerabilities_closed}")
        
        session.commit()
        close_time = time.time() - close_start
        print(f"✅ Old relationships closed successfully in {close_time:.1f}s")

        step_time = time.time() - step_start
        print(f"✅ Step 6 completed in {step_time:.1f}s")

        total_time = time.time() - start_time
        print(f"🎉 Fast processing completed!")
        print(f"⏰ Total time: {total_time:.1f}s ({total_time/60:.1f} minutes)")
        print(f"📊 Processed {len(scan_details):,} items at {len(scan_details)/total_time:.0f} items/second")
        print(f"🎯 Completed at: {time.strftime('%H:%M:%S')}")
        
    except Exception as e:
        total_time = time.time() - start_time
        print(f"❌ Fast processing error after {total_time:.1f}s: {e}")
        session.rollback()
        raise
    finally:
        session.close()

def store_scan_results_auto(scan_json, isinventoryscan: bool = False):
    """
    Automatically select the best processing method based on dataset size and system resources
    """
    scan_details = scan_json.get("scan_details", []) if isinstance(scan_json, dict) else scan_json
    data_size = len(scan_details)
    
    method = get_optimal_processing_method(data_size)
    print(f"Auto-selected {method} processing for {data_size:,} items")
    
    if method == "standard":
        return store_scan_results(scan_json, isinventoryscan)
    elif method == "fast":
        return store_scan_results_fast(scan_json, isinventoryscan)
    else:
        # Fallback to fast processing
        return store_scan_results_fast(scan_json, isinventoryscan)

# Thread-local storage for database sessions
import threading
_thread_local = threading.local()

def get_thread_session():
    """Get a database session for the current thread"""
    if not hasattr(_thread_local, 'session'):
        _thread_local.session = SessionLocal()
    return _thread_local.session

def close_thread_session():
    """Close the database session for the current thread"""
    if hasattr(_thread_local, 'session'):
        _thread_local.session.close()
        del _thread_local.session

def bulk_insert_vulnerabilities(vulnerabilities_data):
    """
    Bulk insert vulnerabilities for maximum performance
    """
    session = get_thread_session()
    try:
        # Prepare bulk insert data
        bulk_data = []
        for vuln_data in vulnerabilities_data:
            bulk_data.append({
                'pluginid': vuln_data['pluginid'],
                'pluginfamily': vuln_data.get('pluginfamily'),
                'pluginname': vuln_data['pluginname'],
                'severity': vuln_data['severity'],
                'description': vuln_data.get('description'),
                'solution': vuln_data.get('solution'),
                'synopsis': vuln_data.get('synopsis'),
                'cpe': vuln_data.get('cpe'),
                'cvss_base_score': vuln_data.get('cvss_base_score'),
                'month_of_discovery': vuln_data['month_of_discovery'],
                'plugin_output': vuln_data.get('plugin_output')
            })
        
        # Use bulk insert
        session.execute(Vulnerability.__table__.insert(), bulk_data)
        session.commit()
        return len(bulk_data)
    except Exception as e:
        session.rollback()
        raise
    finally:
        close_thread_session()

def bulk_insert_hosts(hosts_data):
    """
    Bulk insert hosts for maximum performance
    """
    session = get_thread_session()
    try:
        # Prepare bulk insert data
        bulk_data = []
        for host_data in hosts_data:
            bulk_data.append({
                'hostname': host_data['hostname'],
                'host_ip': host_data['host_ip'],
                'last_scan_date': host_data.get('last_scan_date'),
                'status': host_data['status'],
                'server_owner': host_data.get('server_owner'),
                'os_name': host_data.get('os_name', 'Unknown')
            })
        
        # Use bulk insert
        session.execute(Host.__table__.insert(), bulk_data)
        session.commit()
        return len(bulk_data)
    except Exception as e:
        session.rollback()
        raise
    finally:
        close_thread_session()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    ""
)

# Optimized engine configuration for better performance
engine = create_engine(
    DATABASE_URL,
    pool_size=int(os.getenv("DB_POOL_SIZE", "20")),  # Increase connection pool size
    max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "30")),  # Allow more connections when pool is full
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "3600")),  # Recycle connections every hour
    echo=False  # Disable SQL logging for production
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Ensure host_vulnerability has plugin_output column (runtime migration safeguard)
def ensure_host_vuln_plugin_output_column():
    session = SessionLocal()
    try:
        check_column_query = text(
            """
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'host_vulnerability'
              AND column_name = 'plugin_output'
            """
        )
        exists = session.execute(check_column_query).scalar()
        if exists == 0:
            session.execute(text("ALTER TABLE host_vulnerability ADD COLUMN plugin_output TEXT NULL"))
            session.commit()
            print("✅ Added host_vulnerability.plugin_output column")
    except Exception as e:
        session.rollback()
        print(f"⚠️ Could not ensure host_vulnerability.plugin_output column: {e}")
    finally:
        session.close()

# Run the safeguard at import time
ensure_host_vuln_plugin_output_column()

def extract_hostname_from_plugin_output(output):
    # Look for 'Common Name: <hostname>' in the plugin output
    match = re.search(r"Common Name:\s*([^\s]+)", output)
    if match:
        return match.group(1).strip()
    return None

def extract_os_from_plugin_output(output):
    # Extract OS information from plugin ID 11936 output
    if not output:
        return "Unknown"
    
    # Look for 'Remote operating system : <os_info>' in the plugin output
    match = re.search(r"Remote operating system\s*:\s*(.+?)\s*\n", output)
    if match:
        os_info = match.group(1).strip().lower()
        if "windows" in os_info:
            return "Windows"
        elif "linux" in os_info:
            return "Linux"
    
    return "Unknown"

def risk_string_to_int(risk):
    if not risk:
        return None
    risk = str(risk).strip().lower()
    mapping = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
        "unknown": None  # Map unknown to None
    }
    return mapping.get(risk, None)

def process_chunk_parallel(chunk_data, isinventoryscan=False):
    """
    Process a chunk of scan data in parallel with optimized bulk operations
    """
    session = get_thread_session()
    try:
        chunk_details = chunk_data.get("scan_details", [])
        
        # Pre-process data for this chunk
        host_os_info = {}
        host_vulns_in_scan = defaultdict(set)
        host_plugin_output = {}
        vulnerabilities_to_create = []
        vulnerabilities_to_update = []
        hosts_to_create = []
        hosts_to_update = []
        host_vuln_links_to_create = []
        vulnerabilities_to_create_ids = set()  # Track which plugin_ids we're adding
        
        # Get unique host IPs and plugin IDs for this chunk
        unique_host_ips = set()
        unique_plugin_ids = set()
        
        # First pass: collect data and extract OS information
        for detail in chunk_details:
            host_ip = detail.get("Host")
            plugin_id = detail.get("Plugin ID")
            
            if host_ip:
                unique_host_ips.add(host_ip)
            
            if plugin_id:
                unique_plugin_ids.add(plugin_id)
            
            # Extract OS information from plugin ID 11936
            if str(plugin_id) == "11936" and detail.get("Plugin Output"):
                os_name = extract_os_from_plugin_output(detail.get("Plugin Output"))
                host_os_info[host_ip] = os_name

        # Batch query existing hosts and vulnerabilities for this chunk
        existing_hosts = {
            host.host_ip: host 
            for host in session.query(Host).filter(Host.host_ip.in_(unique_host_ips)).all()
        }
        
        existing_vulns = {
            vuln.pluginid: vuln 
            for vuln in session.query(Vulnerability).filter(Vulnerability.pluginid.in_(unique_plugin_ids)).all()
        }

        # Process vulnerabilities in this chunk
        for detail in chunk_details:
            host_ip = detail.get("Host")
            plugin_id = detail.get("Plugin ID")
            plugin_name = detail.get("Name")
            plugin_output = detail.get("Plugin Output")
            
            # Track all hosts that were scanned, regardless of vulnerability severity
            # This ensures we can close old vulnerabilities even if host only has low/no severity vulns
            if host_ip:
                # Initialize the set for this host if it doesn't exist
                if host_ip not in host_vulns_in_scan:
                    host_vulns_in_scan[host_ip] = set()
            
            severity = risk_string_to_int(detail.get("Risk"))
            if severity is None or severity < 2:
                continue

            host_vulns_in_scan[host_ip].add(plugin_id)
            if host_ip and plugin_id is not None:
                host_plugin_output[(host_ip, plugin_id)] = plugin_output

            # Handle Host creation/update
            if host_ip not in existing_hosts:
                os_name = host_os_info.get(host_ip, "Unknown")
                hosts_to_create.append({
                    'hostname': host_ip,
                    'host_ip': host_ip,
                    'last_scan_date': None,
                    'status': 'online',
                    'server_owner': None,
                    'os_name': os_name
                })
                # Create a mock host object for tracking
                existing_hosts[host_ip] = type('MockHost', (), {'id': None, 'host_ip': host_ip})()
            else:
                host = existing_hosts[host_ip]
                if not isinventoryscan:
                    host.last_scan_date = datetime.now()
                    print(f"🔄 Updated last_scan_date for host {host.host_ip} to {host.last_scan_date}")
                if host_ip in host_os_info:
                    host.os_name = host_os_info[host_ip]
                hosts_to_update.append(host)

            # Handle Vulnerability creation/update
            if plugin_id not in existing_vulns and plugin_id not in vulnerabilities_to_create_ids:
                month_str = datetime.now().strftime("%Y-%m")
                vulnerabilities_to_create.append({
                    'pluginid': plugin_id,
                    'pluginfamily': None,
                    'pluginname': plugin_name,
                    'severity': severity,
                    'description': detail.get("Description"),
                    'solution': detail.get("Solution"),
                    'synopsis': detail.get("Synopsis"),
                    'cpe': detail.get("CVE"),
                    'cvss_base_score': None,
                    'month_of_discovery': month_str
                })
                vulnerabilities_to_create_ids.add(plugin_id)  # Track that we've added this plugin_id
                # Create a mock vuln object for tracking
                existing_vulns[plugin_id] = type('MockVuln', (), {'pluginid': plugin_id})()
            else:
                # No Vulnerability.plugin_output updates; keep existing_vulns entry
                pass

        # Use bulk operations for better performance with retry logic
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # Use bulk operations for better performance
                if hosts_to_create:
                    bulk_insert_hosts(hosts_to_create)

                if vulnerabilities_to_create:
                    bulk_insert_vulnerabilities(vulnerabilities_to_create)

                # Handle updates and relationships with shorter transactions
                if hosts_to_update:
                    # Update hosts in smaller batches to avoid locks
                    batch_size = 10
                    for i in range(0, len(hosts_to_update), batch_size):
                        batch = hosts_to_update[i:i + batch_size]
                        session.add_all(batch)
                        session.commit()
                        session.rollback()  # Clear session for next batch

                # No Vulnerability updates here; plugin_output stored on association

                # Handle host-vulnerability relationships for this chunk
                for host_ip, plugin_ids_in_scan in host_vulns_in_scan.items():
                    host = existing_hosts[host_ip]
                    
                    # Skip if host was just created (no ID yet)
                    if host.id is None:
                        continue
                        
                    existing_links = session.execute(
                        host_vulnerability.select().where(host_vulnerability.c.host_id == host.id)
                    ).fetchall()
                    existing_vuln_ids = {link.vulnerability_id for link in existing_links}
                    
                    for plugin_id in plugin_ids_in_scan:
                        vuln = existing_vulns.get(plugin_id)
                        
                        if vuln and plugin_id not in existing_vuln_ids:
                            host_vuln_links_to_create.append({
                                'host_id': host.id,
                                'vulnerability_id': plugin_id,
                                'vuln_status': 'active',
                                'plugin_output': host_plugin_output.get((host_ip, plugin_id))
                            })
                        elif vuln and plugin_id in existing_vuln_ids:
                            session.execute(
                                host_vulnerability.update()
                                .where(
                                    (host_vulnerability.c.host_id == host.id) &
                                    (host_vulnerability.c.vulnerability_id == plugin_id)
                                )
                                .values(
                                    vuln_status="active",
                                    plugin_output=host_plugin_output.get((host_ip, plugin_id))
                                )
                            )

                # Batch insert host-vulnerability links
                if host_vuln_links_to_create:
                    session.execute(host_vulnerability.insert(), host_vuln_links_to_create)

                session.commit()
                break  # Success, exit retry loop
                
            except Exception as e:
                retry_count += 1
                session.rollback()
                print(f"Database operation failed (attempt {retry_count}/{max_retries}): {e}")
                
                if retry_count >= max_retries:
                    raise e
                
                # Wait before retry with exponential backoff
                import time
                time.sleep(2 ** retry_count)  # 2, 4, 8 seconds
        
        return len(chunk_details)
        
    except Exception as e:
        print(f"Error in parallel chunk processing: {e}")
        session.rollback()
        raise
    finally:
        close_thread_session()

async def store_scan_results_async(scan_json, isinventoryscan: bool = False, max_concurrent: int = 4):
    """
    Async processing version for maximum performance with database operations
    """
    scan_details = scan_json.get("scan_details", []) if isinstance(scan_json, dict) else scan_json
    
    if len(scan_details) < 1000:
        # For small datasets, use the regular optimized function
        return store_scan_results(scan_json, isinventoryscan)
    
    print(f"Processing large dataset with {len(scan_details)} items using async processing")
    
    # Split data into chunks for async processing
    chunk_size = max(500, len(scan_details) // (max_concurrent * 2))
    chunks = []
    
    for i in range(0, len(scan_details), chunk_size):
        chunk = scan_details[i:i + chunk_size]
        chunks.append({"scan_details": chunk})
    
    print(f"Split into {len(chunks)} chunks of ~{chunk_size} items each")
    
    # Process chunks concurrently using asyncio
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def process_chunk_async(chunk_data, chunk_index):
        async with semaphore:
            # Run the CPU-intensive processing in a thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                result = await loop.run_in_executor(
                    executor, 
                    process_chunk_parallel, 
                    chunk_data, 
                    isinventoryscan
                )
            print(f"Completed async chunk {chunk_index + 1}/{len(chunks)} ({result} items processed)")
            return result
    
    # Create tasks for all chunks
    tasks = [
        process_chunk_async(chunk, i) 
        for i, chunk in enumerate(chunks)
    ]
    
    # Wait for all tasks to complete
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Check for errors
    errors = [r for r in results if isinstance(r, Exception)]
    if errors:
        print(f"Errors occurred in {len(errors)} chunks:")
        for error in errors:
            print(f"  - {error}")
        raise errors[0] if errors else Exception("Unknown error in async processing")
    
    total_processed = sum(results)
    print(f"Async processing completed. Total items processed: {total_processed}")

def store_scan_results_parallel(scan_json, isinventoryscan: bool = False, max_workers: int = None):
    """
    Parallel processing version for maximum performance
    """
    if max_workers is None:
        max_workers = PARALLEL_CONFIG['max_workers']
    
    scan_details = scan_json.get("scan_details", []) if isinstance(scan_json, dict) else scan_json
    
    if len(scan_details) < 1000:
        # For small datasets, use the regular optimized function
        return store_scan_results(scan_json, isinventoryscan)
    
    print(f"Processing large dataset with {len(scan_details)} items using {max_workers} parallel workers")
    
    # Split data into chunks for parallel processing
    chunk_size = max(100, len(scan_details) // (max_workers * 2))  # Ensure reasonable chunk size
    chunks = []
    
    for i in range(0, len(scan_details), chunk_size):
        chunk = scan_details[i:i + chunk_size]
        chunks.append({"scan_details": chunk})
    
    print(f"Split into {len(chunks)} chunks of ~{chunk_size} items each")
    
    # Process chunks in parallel using ThreadPoolExecutor (better for I/O bound operations)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all chunks for processing
        future_to_chunk = {
            executor.submit(process_chunk_parallel, chunk, isinventoryscan): i 
            for i, chunk in enumerate(chunks)
        }
        
        # Collect results and track progress
        completed = 0
        total_chunks = len(chunks)
        
        for future in future_to_chunk:
            try:
                processed_count = future.result()
                completed += 1
                print(f"Completed chunk {completed}/{total_chunks} ({processed_count} items processed)")
            except Exception as e:
                print(f"Error processing chunk: {e}")
                raise
    
    print(f"Parallel processing completed. Total items processed: {len(scan_details)}")

def store_scan_results_optimized(scan_json, isinventoryscan: bool = False, chunk_size: int = 1000):
    """
    Optimized version for very large datasets that processes data in chunks
    """
    session = SessionLocal()
    try:
        scan_details = scan_json.get("scan_details", []) if isinstance(scan_json, dict) else scan_json
        
        if len(scan_details) <= chunk_size:
            # Use the regular optimized function for smaller datasets
            return store_scan_results(scan_json, isinventoryscan)
        
        print(f"Processing large dataset with {len(scan_details)} items in chunks of {chunk_size}")
        
        # Process in chunks
        for i in range(0, len(scan_details), chunk_size):
            chunk = scan_details[i:i + chunk_size]
            chunk_json = {"scan_details": chunk}
            
            print(f"Processing chunk {i//chunk_size + 1}/{(len(scan_details) + chunk_size - 1)//chunk_size}")
            
            # Process this chunk
            store_scan_results(chunk_json, isinventoryscan)
            
        print("Large dataset processing completed")
        
    except Exception as e:
        print("DB Error in optimized processing:", e)
        raise
    finally:
        session.close()

def store_scan_results(scan_json, isinventoryscan: bool = False):
    session = SessionLocal()
    try:
        scan_details = scan_json.get("scan_details", []) if isinstance(scan_json, dict) else scan_json

        # Pre-process data for batch operations
        host_os_info = {}
        host_vulns_in_scan = defaultdict(set)
        host_plugin_output = {}
        vulnerabilities_to_create = []
        vulnerabilities_to_update = []
        hosts_to_create = []
        hosts_to_update = []
        host_vuln_links_to_create = []
        host_vuln_links_to_update = []
        vulnerabilities_to_create_ids = set()  # Track which plugin_ids we're adding
        
        # Get all unique host IPs and plugin IDs for batch queries
        unique_host_ips = set()
        unique_plugin_ids = set()
        
        # First pass: collect all data and extract OS information
        for detail in scan_details:
            host_ip = detail.get("Host")
            plugin_id = detail.get("Plugin ID")
            
            if host_ip:
                unique_host_ips.add(host_ip)
            
            if plugin_id:
                unique_plugin_ids.add(plugin_id)
            
            # Extract OS information from plugin ID 11936
            if str(plugin_id) == "11936" and detail.get("Plugin Output"):
                os_name = extract_os_from_plugin_output(detail.get("Plugin Output"))
                host_os_info[host_ip] = os_name
                print(f"Found OS for {host_ip}: {os_name}")

        # Batch query existing hosts
        existing_hosts = {
            host.host_ip: host 
            for host in session.query(Host).filter(Host.host_ip.in_(unique_host_ips)).all()
        }
        
        # Batch query existing vulnerabilities
        existing_vulns = {
            vuln.pluginid: vuln 
            for vuln in session.query(Vulnerability).filter(Vulnerability.pluginid.in_(unique_plugin_ids)).all()
        }


        # Second pass: process vulnerabilities and prepare batch operations
        # Track which hosts have been updated for scan date
        updated_hosts = set()
        for detail in scan_details:
            host_ip = detail.get("Host")
            plugin_id = detail.get("Plugin ID")
            plugin_name = detail.get("Name")
            plugin_output = detail.get("Plugin Output")
            severity = risk_string_to_int(detail.get("Risk"))

            # Always update host scan date, even if only low/info vulnerabilities are present
            if host_ip:
                if host_ip not in updated_hosts:
                    if host_ip not in existing_hosts:
                        # New host to create
                        os_name = host_os_info.get(host_ip, "Unknown")
                        new_host = Host(
                            hostname=host_ip,
                            host_ip=host_ip,
                            last_scan_date=None if isinventoryscan else datetime.now(),
                            status="online",
                            server_owner=None,
                            os_name=os_name
                        )
                        hosts_to_create.append(new_host)
                        existing_hosts[host_ip] = new_host  # Add to dict for later use
                    else:
                        # Existing host to update
                        host = existing_hosts[host_ip]
                        host.status = "online"
                        if not isinventoryscan:
                            host.last_scan_date = datetime.now()
                            print(f"🔄 Updated last_scan_date for host {host.host_ip} to {host.last_scan_date}")
                        if host_ip in host_os_info:
                            host.os_name = host_os_info[host_ip]
                        hosts_to_update.append(host)
                    updated_hosts.add(host_ip)

            # Track all hosts that were scanned, regardless of vulnerability severity
            # This ensures we can close old vulnerabilities even if host only has low/no severity vulns
            if host_ip:
                # Initialize the set for this host if it doesn't exist
                if host_ip not in host_vulns_in_scan:
                    host_vulns_in_scan[host_ip] = set()

            # Only process vulnerabilities with severity medium or higher for storage
            if severity is None or severity < 2:
                continue

            # Track plugin_ids per host for this scan (only medium+ severity)
            host_vulns_in_scan[host_ip].add(plugin_id)
            if host_ip and plugin_id is not None:
                host_plugin_output[(host_ip, plugin_id)] = plugin_output

            # Handle Vulnerability creation/update
            if plugin_id not in existing_vulns and plugin_id not in vulnerabilities_to_create_ids:
                # New vulnerability to create
                month_str = datetime.now().strftime("%Y-%m")
                new_vuln = Vulnerability(
                    pluginid=plugin_id,
                    pluginfamily=None,
                    pluginname=plugin_name,
                    severity=severity,
                    description=detail.get("Description"),
                    solution=detail.get("Solution"),
                    synopsis=detail.get("Synopsis"),
                    cpe=detail.get("CVE"),
                    cvss_base_score=None,
                    month_of_discovery=month_str
                )
                vulnerabilities_to_create.append(new_vuln)
                vulnerabilities_to_create_ids.add(plugin_id)  # Track that we've added this plugin_id
                existing_vulns[plugin_id] = new_vuln
            else:
                # No Vulnerability.plugin_output updates here
                pass

        # Batch create hosts
        if hosts_to_create:
            session.add_all(hosts_to_create)
            session.flush()  # Flush once to get IDs

        # Batch create vulnerabilities
        if vulnerabilities_to_create:
            session.add_all(vulnerabilities_to_create)
            session.flush()  # Flush once to get IDs

        # Batch update hosts
        if hosts_to_update:
            session.add_all(hosts_to_update)

        # No Vulnerability updates needed here

        # Handle host-vulnerability relationships efficiently
        # Skip vulnerability processing for inventory scans - we only want to track host availability
        if not isinventoryscan:
            for host_ip, plugin_ids_in_scan in host_vulns_in_scan.items():
                host = existing_hosts[host_ip]
                
                # Get existing host-vulnerability links for this host
                existing_links = session.execute(
                    host_vulnerability.select().where(host_vulnerability.c.host_id == host.id)
                ).fetchall()
                existing_vuln_ids = {link.vulnerability_id for link in existing_links}
                
                # Prepare batch operations for host-vulnerability links
                for plugin_id in plugin_ids_in_scan:
                    vuln = existing_vulns.get(plugin_id)
                    
                    if vuln and plugin_id not in existing_vuln_ids:
                        # New link to create
                        host_vuln_links_to_create.append({
                            'host_id': host.id,
                            'vulnerability_id': plugin_id,
                            'vuln_status': 'active',
                            'plugin_output': host_plugin_output.get((host_ip, plugin_id))
                        })
                    elif vuln and plugin_id in existing_vuln_ids:
                        # Existing link to update status and plugin_output
                        session.execute(
                            host_vulnerability.update()
                            .where(
                                (host_vulnerability.c.host_id == host.id) &
                                (host_vulnerability.c.vulnerability_id == plugin_id)
                            )
                            .values(
                                vuln_status="active",
                                plugin_output=host_plugin_output.get((host_ip, plugin_id))
                            )
                        )

            # Batch insert host-vulnerability links
            if host_vuln_links_to_create:
                session.execute(host_vulnerability.insert(), host_vuln_links_to_create)
        else:
            print("ℹ️  Skipping vulnerability processing for inventory scan - only tracking host availability")

        # Existing links already updated above

        # Close vulnerabilities not present in this scan for all hosts in scan
        # Skip this for inventory scans - we only want to track host availability, not vulnerability changes
        if not isinventoryscan:
            for host_ip in unique_host_ips:
                host = existing_hosts.get(host_ip)
                if not host:
                    continue
                # Get all existing links for this host
                existing_links = session.execute(
                    host_vulnerability.select().where(host_vulnerability.c.host_id == host.id)
                ).fetchall()
                # Get plugin_ids found in this scan for this host
                plugin_ids_in_scan = host_vulns_in_scan.get(host_ip, set())
                for link in existing_links:
                    if link.vulnerability_id not in plugin_ids_in_scan:
                        session.execute(
                            host_vulnerability.update()
                            .where(
                                (host_vulnerability.c.host_id == host.id) &
                                (host_vulnerability.c.vulnerability_id == link.vulnerability_id)
                            )
                            .values(vuln_status="closed", closed_date=datetime.utcnow())
                        )
        else:
            print("ℹ️  Skipping vulnerability closure for inventory scan - only tracking host availability")

        # Handle inventory scan logic
        if isinventoryscan:
            print("📋 Processing inventory scan logic...")
            
            # Mark all hosts found in this scan as online
            hosts_marked_online = 0
            hosts_created = 0
            for host_ip in unique_host_ips:
                if host_ip not in existing_hosts:
                    # Create new host
                    os_name = host_os_info.get(host_ip, "Unknown")
                    new_host = Host(
                        hostname=host_ip,
                        host_ip=host_ip,
                        last_scan_date=None,
                        status="online",
                        server_owner=None,
                        os_name=os_name
                    )
                    session.add(new_host)
                    hosts_created += 1
                    print(f"➕ Created new host {host_ip} as online")
                else:
                    # Update existing host to online (only if it wasn't already online)
                    host = existing_hosts[host_ip]
                    if host.status != "online":
                        host.status = "online"
                        hosts_marked_online += 1
                        print(f"🔄 Marked existing host {host_ip} as online (was {host.status})")
                    if host_ip in host_os_info:
                        host.os_name = host_os_info[host_ip]
                    session.add(host)
            
            print(f"✅ Created {hosts_created} new hosts and marked {hosts_marked_online} existing hosts as online")
            
            # Only mark hosts as offline if they were previously online and are not in this scan
            all_existing_hosts = session.query(Host).all()
            hosts_in_scan = set(unique_host_ips)
            
            hosts_marked_offline = 0
            vulnerabilities_closed = 0
            
            for host in all_existing_hosts:
                if host.host_ip not in hosts_in_scan and host.status == "online":
                    # Host was online but not found in scan - mark as offline
                    host.status = "offline"
                    session.add(host)
                    hosts_marked_offline += 1
                    
                    # Count vulnerabilities that will be closed
                    vuln_count = session.execute(
                        host_vulnerability.select()
                        .where(host_vulnerability.c.host_id == host.id)
                        .where(host_vulnerability.c.vuln_status == "active")
                    ).rowcount
                    
                    # Close all active vulnerabilities associated with this offline host
                    if vuln_count > 0:
                        session.execute(
                            host_vulnerability.update()
                            .where(host_vulnerability.c.host_id == host.id)
                            .where(host_vulnerability.c.vuln_status == "active")
                            .values(vuln_status="closed", closed_date=datetime.utcnow())
                        )
                        vulnerabilities_closed += vuln_count
                        print(f"🔒 Marked host {host.host_ip} as offline and closed {vuln_count} vulnerabilities")
                    else:
                        print(f"🔒 Marked host {host.host_ip} as offline (no active vulnerabilities to close)")
                elif host.host_ip not in hosts_in_scan and host.status != "online":
                    print(f"ℹ️  Host {host.host_ip} was already {host.status}, no action needed")
            
            print(f"📊 Inventory scan summary:")
            print(f"   - Hosts in scan: {len(hosts_in_scan)}")
            print(f"   - New hosts created: {hosts_created}")
            print(f"   - Hosts marked online: {hosts_marked_online}")
            print(f"   - Hosts marked offline: {hosts_marked_offline}")
            print(f"   - Vulnerabilities closed: {vulnerabilities_closed}")

        session.commit()
        print(f"Successfully processed {len(scan_details)} scan details")
        
    except Exception as e:
        print("DB Error:", e)
        session.rollback()
        raise
    finally:
        session.close()

def store_scan_results_hybrid(scan_json, isinventoryscan: bool = False):
    """
    Hybrid approach: combines parallel and async processing for maximum performance
    """
    scan_details = scan_json.get("scan_details", []) if isinstance(scan_json, dict) else scan_json
    
    if len(scan_details) < 2000:
        # For smaller datasets, use parallel processing
        return store_scan_results_parallel(scan_json, isinventoryscan)
    
    print(f"Using hybrid processing for {len(scan_details)} items")
    
    # Use async processing for very large datasets
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(
            store_scan_results_async(scan_json, isinventoryscan)
        )
    finally:
        loop.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
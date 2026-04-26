from sqlalchemy import create_engine, Column, Integer, String, DateTime, false, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import requests
from bs4 import BeautifulSoup
import re
import json
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import time
import asyncio
import base64
import pandas as pd
from io import StringIO
import aiohttp
import os
import sys
import argparse
import pytz
import smtplib
from config.settings import Config
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress SSL warnings for Nessus API calls
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Database connection string from environment variables
DATABASE_URL = os.getenv("DATABASE_URL", "")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()



class BatchScan(Base):
    __tablename__ = "batch_scans"
    id = Column(Integer, primary_key=True, index=True)
    batch_name = Column(String(255), nullable=False)
    batch_size = Column(Integer, nullable=False)
    batch_job = Column(String(50), nullable=False)  # 'vuln scan' or 'compliance scan'
    job_start_time = Column(String(20), nullable=False)  # e.g., '14:00'
    job_end_time = Column(String(20), nullable=False)    # e.g., '16:00'
    week_day = Column(String(20), nullable=False)        # e.g., 'Monday' or '0-6'
    created_at = Column(DateTime, default=datetime.utcnow)




class Host(Base):
    __tablename__ = "hosts"
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), unique=False, index=True)
    host_ip = Column(String(255), unique=False, index=True)
    last_scan_date = Column(DateTime)
    status = Column(String(50))
    server_owner = Column(String(255), nullable=True)
    application_dependent = Column(String(255), nullable=True)
    os_name = Column(String(50), nullable=True, default="Unknown")
    ready_for_rescan = Column(Boolean, default=False, nullable=False)  # Toggle for immediate rescan

class IntegrationConfig(Base):
    __tablename__ = "integration_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    integration_type = Column(String(50), nullable=False)
    enabled = Column(Boolean, default=False)
    config_data = Column(Text, nullable=True)
    status = Column(String(50), default="not_configured")
    last_tested = Column(DateTime, nullable=True)
    last_sync = Column(DateTime, nullable=True)
    extra_metadata = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

def get_nessus_config():
    """Get Nessus configuration from database"""
    session = SessionLocal()
    try:
        integration = session.query(IntegrationConfig).filter(
            IntegrationConfig.integration_type == "nessus",
            IntegrationConfig.enabled == True
        ).first()
        
        if not integration:
            print("No enabled Nessus integration found in database")
            return None
            
        if not integration.config_data:
            print("No configuration data found for Nessus integration")
            return None
            
        config_data = json.loads(integration.config_data)
        
        # Validate required fields
        required_fields = ["serverUrl", "username", "password"]
        for field in required_fields:
            if field not in config_data or not config_data[field]:
                print(f"Missing required field '{field}' in Nessus configuration")
                return None
        
        return {
            "server_url": config_data["serverUrl"],
            "username": config_data["username"],
            "password": config_data["password"]
        }
        
    except json.JSONDecodeError as e:
        print(f"Error parsing Nessus configuration JSON: {e}")
        return None
    except Exception as e:
        print(f"Error retrieving Nessus configuration: {e}")
        return None
    finally:
        session.close()

def get_top_oldest_hosts(batch_size=2):
    session = SessionLocal()
    try:
        hosts = (
            session.query(Host)
            .order_by(Host.last_scan_date.is_(None).desc(), Host.last_scan_date.asc())
            .limit(batch_size)
            .all()
        )
        result = []
        for host in hosts:
            result.append((host.host_ip,host.os_name, host.last_scan_date.isoformat() if host.last_scan_date else "No date"))
        return result
    finally:
        session.close()



def get_nessus_token():
    # Get Nessus configuration from database
    nessus_config = get_nessus_config()
    if not nessus_config:
        print("Failed to get Nessus configuration from database")
        return None, None
    
    server_url = nessus_config["server_url"]
    username = nessus_config["username"]
    password = nessus_config["password"]
    
    # Ensure server URL ends with /
    if not server_url.endswith('/'):
        server_url += '/'
    
    print(f"Using Nessus server: {server_url}")
    
    # Make the initial GET request
    response = requests.get(server_url, verify=False)  # verify=False is used to ignore SSL certificate warnings
    time.sleep(2)  # Delay after API call
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        script_tag = soup.find('script', src=lambda x: x and 'nessus6.js' in x)
        if script_tag:
            script_src = script_tag['src']
            script_url = f"{server_url.rstrip('/')}/{script_src}"
            script_response = requests.get(script_url, verify=False)
            time.sleep(2)  # Delay after API call
            if script_response.status_code == 200:
                script_content = script_response.text
                match = re.search(r'key\s*:\s*"getApiToken",\s*value\s*:\s*function\(\)\s*{\s*return\s*"([^"]+)"\s*}', script_content)
                if match:
                    get_api_token = match.group(1)
                    print(f"getApiToken value: {get_api_token}")
                else:
                    print("getApiToken value not found.")
                    return None, None
            else:
                print(f"Failed to retrieve the script file. Status code: {script_response.status_code}")
                return None, None
        else:
            print("Script tag not found.")
            return None, None
    else:
        print(f"Failed to retrieve the page. Status code: {response.status_code}")
        return None, None

    Session_url = f"{server_url.rstrip('/')}/session"
    payload = {"username": username, "password": password}
    headers_Session_url = {
        "X-Api-Token": get_api_token,
        "content-type": "application/json",
    }
    response = requests.post(Session_url, json=payload, headers=headers_Session_url, verify=False)
    time.sleep(2)  # Delay after API call
    response_data = json.loads(response.text)
    token = response_data.get("token")
    print(token)
    return get_api_token, token


def update_and_launch_scan(get_api_token, token, ips, policy_id, os_name_label):
    # Get Nessus configuration from database
    nessus_config = get_nessus_config()
    if not nessus_config:
        print("Failed to get Nessus configuration from database")
        return False
    
    server_url = nessus_config["server_url"].rstrip('/')
    Update_url = f"{server_url}/scans/5308"
    headers_Update_url = {
        "X-Api-Token": get_api_token,
        "content-type": "application/json",
        "X-Cookie": f"token={token}"
    }
    payload = {
        # uuid linux ab4bacd2-05f6-425c-9d79-3ba3940ad1c24e51e1f403febe40 3231
        # uuid windows ab4bacd2-05f6-425c-9d79-3ba3940ad1c24e51e1f403febe40 3246
        # scan uuid "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66"
        "uuid": "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66",
        "settings": {
            "name": f"SCAN_{os_name_label.upper()}",
            "policy_id": str(policy_id),
            "folder_id": 5306,
            "text_targets": ips
        }
    }
    
    # Try to update scan with retry logic
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        response = requests.put(Update_url, json=payload, headers=headers_Update_url, verify=False)
        time.sleep(2)  # Delay after API call
        if response.status_code == 200:
            print(f"Scan updated successfully for {os_name_label} hosts!")
            break
        elif response.status_code == 401:
            print("Authentication failed during scan update. Attempting to refresh token...")
            try:
                new_get_api_token, new_token = get_nessus_token()
                if new_get_api_token and new_token:
                    get_api_token = new_get_api_token
                    token = new_token
                    headers_Update_url = {
                        "X-Api-Token": get_api_token,
                        "content-type": "application/json",
                        "X-Cookie": f"token={token}"
                    }
                    retry_count += 1
                    print(f"Token refreshed for scan update. Retry attempt {retry_count}/{max_retries}")
                    continue
                else:
                    print("Failed to refresh token for scan update.")
                    return False
            except Exception as e:
                print(f"Error refreshing token for scan update: {e}")
                return False
        else:
            print(f"Failed to update scan for {os_name_label} hosts. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return False
    
    if retry_count >= max_retries:
        print(f"Max retries exceeded for scan update.")
        return False
    
    # Launch scan with retry logic
    Lanuch_url = f"{server_url}/scans/5308/launch"
    headers_Lanuch_url = {
        "X-Api-Token": get_api_token,
        "content-type": "application/json",
        "X-Cookie": f"token={token}"
    }
    payload_launch = {}
    
    retry_count = 0
    while retry_count < max_retries:
        response = requests.post(Lanuch_url, json=payload_launch, headers=headers_Lanuch_url, verify=False)
        time.sleep(2)  # Delay after API call
        if response.status_code == 200:
            print(f"Scan launched successfully for {os_name_label} hosts!")
            return True
        elif response.status_code == 401:
            print("Authentication failed during scan launch. Attempting to refresh token...")
            try:
                new_get_api_token, new_token = get_nessus_token()
                if new_get_api_token and new_token:
                    get_api_token = new_get_api_token
                    token = new_token
                    headers_Lanuch_url = {
                        "X-Api-Token": get_api_token,
                        "content-type": "application/json",
                        "X-Cookie": f"token={token}"
                    }
                    retry_count += 1
                    print(f"Token refreshed for scan launch. Retry attempt {retry_count}/{max_retries}")
                    continue
                else:
                    print("Failed to refresh token for scan launch.")
                    return False
            except Exception as e:
                print(f"Error refreshing token for scan launch: {e}")
                return False
        else:
            print(f"Failed to launch scan for {os_name_label} hosts. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            # Try to print JSON error details if available
            try:
                error_json = response.json()
                print(f"Error details: {json.dumps(error_json, indent=2)}")
            except Exception:
                print("Response is not valid JSON.")
            return False
    
    print(f"Max retries exceeded for scan launch.")
    return False

def check_scan_status(get_api_token, token):
    """Check current scan status without waiting"""
    import time
    import json
    
    # Get Nessus configuration from database
    nessus_config = get_nessus_config()
    if not nessus_config:
        print("Failed to get Nessus configuration from database")
        return None
    
    server_url = nessus_config["server_url"].rstrip('/')
    epoch_time = int(time.time())
    url = f"{server_url}/scans?folder_id=5306&last_modification_date={epoch_time}"
    headers = {
        "X-Api-Token": get_api_token,
        "X-Cookie": f"token={token}"
    }
    
    try:
        response = requests.get(url, headers=headers, verify=False)
        time.sleep(2)  # Delay after API call
        if response.status_code == 200:
            data = json.loads(response.text)
            scans = data.get("scans", [])
            if scans:
                status = scans[0].get("status", "")
                scan_name = scans[0].get("name", "Unknown")
                scan_id = scans[0].get("id", "Unknown")
                return {"status": status, "name": scan_name, "id": scan_id}
            else:
                return {"status": "no_scans", "name": None, "id": None}
        else:
            print(f"Failed to check scan status. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"Exception while checking scan status: {e}")
        return None

def is_scan_running(get_api_token, token):
    """Check if any scan is currently running"""
    scan_info = check_scan_status(get_api_token, token)
    if scan_info is None:
        return True  # Assume running if we can't check (safer)
    
    status = scan_info.get("status", "")
    return status in ["running", "pending"]

def wait_for_existing_scan_completion(get_api_token, token):
    """Wait for any existing running scan to complete before starting new one"""
    print("Checking if any scan is currently running...")
    
    consecutive_failures = 0
    max_consecutive_failures = 5
    wait_time = 0
    
    print("Note: Will wait indefinitely for existing scan to complete before starting new scan.")
    
    while True:
        scan_info = check_scan_status(get_api_token, token)
        
        if scan_info is None:
            consecutive_failures += 1
            print(f"Could not check scan status (failure {consecutive_failures}/{max_consecutive_failures}). Waiting 60 seconds before retrying...")
            if consecutive_failures >= max_consecutive_failures:
                print("Too many consecutive failures checking scan status. Waiting 5 minutes before retrying...")
                time.sleep(300)  # Wait 5 minutes before retrying
                consecutive_failures = 0  # Reset counter after long wait
            else:
                time.sleep(60)
            continue
        
        # Reset failure counter on successful check
        consecutive_failures = 0
        
        status = scan_info.get("status")
        scan_name = scan_info.get("name")
        
        if status in ["running", "pending"]:
            print(f"Scan '{scan_name}' is currently {status}. Waiting 2 minutes before checking again...")
            time.sleep(120)  # Wait 2 minutes between checks
        elif status == "completed":
            print(f"Previous scan '{scan_name}' has completed. Ready to start new scan.")
            return True
        elif status == "no_scans":
            print("No active scans found. Ready to start new scan.")
            return True
        else:
            print(f"Scan status: {status}. Waiting 1 minute before checking again...")
            time.sleep(60)

def wait_for_scan_completion(get_api_token, token):
    import time
    import json
    
    # Get Nessus configuration from database
    nessus_config = get_nessus_config()
    if not nessus_config:
        print("Failed to get Nessus configuration from database")
        return False
    
    server_url = nessus_config["server_url"].rstrip('/')
    epoch_time = int(time.time())
    print(f"Current epoch time: {epoch_time}")
    url = f"{server_url}/scans?folder_id=5306&last_modification_date={epoch_time}"
    headers = {
        "X-Api-Token": get_api_token,
        "X-Cookie": f"token={token}"
    }
    status = None
    max_retries = 3
    retry_count = 0
    consecutive_failures = 0
    max_consecutive_failures = 10
    
    print("Waiting for scan completion...")
    print("Note: Scan completion can take several hours. The script will wait indefinitely until completion.")
    
    while status != "completed":
        
        response = requests.get(url, headers=headers, verify=False)
        time.sleep(10)  # Delay after API call
        
        if response.status_code == 200:
            data = json.loads(response.text)
            scans = data.get("scans", [])
            if scans:
                status = scans[0].get("status", "")
                scan_name = scans[0].get("name", "Unknown")
                print(f"Scan '{scan_name}' status: {status}")
                
                # Reset failure counter on successful check
                consecutive_failures = 0
                
                if status == "completed":
                    print("Scan completed successfully!")
                    return True
                elif status in ["running", "pending"]:
                    print(f"Scan is still {status}. Waiting 2 minutes before checking again...")
                    time.sleep(120)  # Wait 2 minutes between checks
                elif status in ["canceled", "aborted", "error"]:
                    print(f"Scan ended with status: {status}")
                    return False
                else:
                    print(f"Unknown scan status: {status}. Waiting 1 minute before checking again...")
                    time.sleep(60)
            else:
                print("No scans found in the response.")
                consecutive_failures += 1
                if consecutive_failures >= max_consecutive_failures:
                    print("Too many consecutive failures. Scan may have completed or failed.")
                    return False
                time.sleep(30)
        elif response.status_code == 401:
            print("Authentication failed. Attempting to refresh token...")
            if retry_count < max_retries:
                try:
                    # Refresh the token
                    new_get_api_token, new_token = get_nessus_token()
                    if new_get_api_token and new_token:
                        get_api_token = new_get_api_token
                        token = new_token
                        headers = {
                            "X-Api-Token": get_api_token,
                            "X-Cookie": f"token={token}"
                        }
                        retry_count += 1
                        print(f"Token refreshed successfully. Retry attempt {retry_count}/{max_retries}")
                        continue
                    else:
                        print("Failed to refresh token.")
                        return False
                except Exception as e:
                    print(f"Error refreshing token: {e}")
                    return False
            else:
                print(f"Max retries ({max_retries}) exceeded for authentication.")
                return False
        else:
            print(f"Failed to retrieve scan status. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            consecutive_failures += 1
            if consecutive_failures >= max_consecutive_failures:
                print("Too many consecutive failures retrieving scan status.")
                return False
            time.sleep(30)
    
    return False

def get_hosts_by_os(os_name, batch_size):
    session = SessionLocal()
    try:
        query = session.query(Host)
        if os_name == "windows":
            query = query.filter(Host.os_name != None).filter(Host.os_name.ilike("windows"))
        elif os_name == "linux":
            query = query.filter(Host.os_name != None).filter(Host.os_name.ilike("linux"))
        elif os_name == "unknown":
            query = query.filter((Host.os_name == None) | (Host.os_name == "") | (~Host.os_name.ilike("windows")) & (~Host.os_name.ilike("linux")))
        
        # Prioritize hosts with ready_for_rescan = True
        # Order by: ready_for_rescan DESC (True first), then by last_scan_date
        query = query.order_by(
            Host.ready_for_rescan.desc(),  # Ready for rescan hosts first
            Host.last_scan_date.is_(None).desc(), 
            Host.last_scan_date.asc()
        )
        
        hosts = query.limit(batch_size).all()
        result = []
        for host in hosts:
            result.append((host.host_ip, host.os_name, host.last_scan_date.isoformat() if host.last_scan_date else "No date"))
        return result
    finally:
        session.close()

def reset_ready_for_rescan_toggles(host_ips_list):
    """Reset ready_for_rescan toggle to False for hosts that were scanned"""
    session = SessionLocal()
    try:
        # Update all hosts with IPs in the scanned list
        updated_count = session.query(Host).filter(
            Host.host_ip.in_(host_ips_list),
            Host.ready_for_rescan == True
        ).update(
            {Host.ready_for_rescan: False},
            synchronize_session=False
        )
        session.commit()
        
        if updated_count > 0:
            print(f"✅ Reset ready_for_rescan toggle for {updated_count} hosts after scan completion")
        else:
            print("ℹ️ No hosts had ready_for_rescan toggle enabled")
            
        return updated_count
    except Exception as e:
        session.rollback()
        print(f"❌ Error resetting ready_for_rescan toggles: {e}")
        return 0
    finally:
        session.close()

SCAN_STATE_FILE = 'scan_state.txt'
SCAN_LOCK_FILE = 'scan_lock.txt'
# Set your allowed run window (e.g., 1 hour from script start)

def get_run_window_minutes(batch_id):
    if batch_id is None:
        print("No batch_id provided, using default run window of 60 minutes.")
        return 60
    session = SessionLocal()
    try:
        batch = session.query(BatchScan).filter(BatchScan.id == batch_id).first()
        if batch and batch.job_start_time and batch.job_end_time:
            # Parse times with multiple format support and timezone conversion
            from datetime import datetime, timedelta as td
            
            def parse_time_with_timezone(time_str, timezone_str="Asia/Kolkata"):
                time_str = time_str.strip()
                formats_to_try = [
                    "%I:%M %p",  # 08:30 AM
                    "%I:%M%p",   # 08:30AM
                    "%H:%M",     # 08:30 (24-hour)
                    "%I:%M",     # 08:30 (12-hour without AM/PM)
                ]
                
                dt = None
                for fmt in formats_to_try:
                    try:
                        dt = datetime.strptime(time_str, fmt)
                        break
                    except ValueError:
                        continue
                
                if dt is None:
                    raise ValueError(f"Could not parse time: {time_str}")
                
                # Create a simple datetime object for time calculations
                # We'll use the current date with the parsed time
                today = datetime.now().date()
                dt_with_date = datetime.combine(today, dt.time())
                
                return dt_with_date
            
            try:
                start = parse_time_with_timezone(batch.job_start_time)
                end = parse_time_with_timezone(batch.job_end_time)
                
                # If end is before or equal to start, assume it's next day
                if end <= start:
                    end = end + td(days=1)
                
                delta = (end - start).total_seconds() / 60
                print(f"Calculated run window: {delta} minutes from {batch.job_start_time} to {batch.job_end_time} (Kolkata timezone)")
                return int(delta)
            except Exception as e:
                print(f"Error parsing job times: {e}, using default 60 minutes.")
                return 60
        else:
            print("Batch not found or missing job times, using default 60 minutes.")
            return 60
    finally:
        session.close()

OS_SEQUENCE = ['unknown', 'linux', 'windows']

def get_next_os(current_os):
    idx = OS_SEQUENCE.index(current_os)
    return OS_SEQUENCE[(idx + 1) % len(OS_SEQUENCE)]

def read_scan_state():
    if os.path.exists(SCAN_STATE_FILE):
        with open(SCAN_STATE_FILE, 'r') as f:
            state = f.read().strip().lower()
            if state in OS_SEQUENCE:
                return state
    return OS_SEQUENCE[0]  # Default to unknown if no state

def write_scan_state(os_name):
    with open(SCAN_STATE_FILE, 'w') as f:
        f.write(os_name)

def is_scan_locked():
    """Check if a scan is currently locked (running)"""
    if os.path.exists(SCAN_LOCK_FILE):
        try:
            with open(SCAN_LOCK_FILE, 'r') as f:
                lock_data = f.read().strip()
                if lock_data:
                    # Parse lock data: timestamp,pid,os_type
                    parts = lock_data.split(',')
                    if len(parts) >= 2:
                        lock_pid = int(parts[1])
                        # Check if the process is still running
                        try:
                            os.kill(lock_pid, 0)  # Check if process exists
                            print(f"Scan is currently locked by process {lock_pid}")
                            return True
                        except OSError:
                            print(f"Lock process {lock_pid} no longer running, removing stale lock file")
                            os.remove(SCAN_LOCK_FILE)
                            return False
        except Exception as e:
            print(f"Error reading lock file: {e}, removing corrupted lock file")
            os.remove(SCAN_LOCK_FILE)
    return False

def create_scan_lock(os_type):
    """Create a scan lock file"""
    try:
        with open(SCAN_LOCK_FILE, 'w') as f:
            f.write(f"{time.time()},{os.getpid()},{os_type}")
        print(f"Scan lock created for {os_type} scan (PID: {os.getpid()})")
        return True
    except Exception as e:
        print(f"Error creating lock file: {e}")
        return False

def remove_scan_lock():
    """Remove the scan lock file"""
    try:
        if os.path.exists(SCAN_LOCK_FILE):
            os.remove(SCAN_LOCK_FILE)
            print("Scan lock removed successfully")
        return True
    except Exception as e:
        print(f"Error removing lock file: {e}")
        return False

def force_clear_scan_lock():
    """Force clear scan lock file - use with caution"""
    try:
        if os.path.exists(SCAN_LOCK_FILE):
            os.remove(SCAN_LOCK_FILE)
            print("Scan lock force cleared")
            return True
        else:
            print("No scan lock file found")
            return True
    except Exception as e:
        print(f"Error force clearing lock file: {e}")
        return False

def show_scan_lock_status():
    """Show current scan lock status for debugging"""
    if os.path.exists(SCAN_LOCK_FILE):
        try:
            with open(SCAN_LOCK_FILE, 'r') as f:
                lock_data = f.read().strip()
                if lock_data:
                    parts = lock_data.split(',')
                    if len(parts) >= 3:
                        lock_time = float(parts[0])
                        lock_pid = int(parts[1])
                        os_type = parts[2]
                        lock_age = time.time() - lock_time
                        print(f"Scan Lock Status:")
                        print(f"  OS Type: {os_type}")
                        print(f"  Process ID: {lock_pid}")
                        print(f"  Lock Age: {lock_age:.0f} seconds ({lock_age/3600:.1f} hours)")
                        
                        # Check if process is running
                        try:
                            os.kill(lock_pid, 0)
                            print(f"  Process Status: Running")
                            return True
                        except OSError:
                            print(f"  Process Status: Not Running (stale lock)")
                            return False
        except Exception as e:
            print(f"Error reading lock file: {e}")
            return False
    else:
        print("No scan lock file found")
        return False

def is_time_to_end(start_time, run_window_minutes):
    return datetime.now() >= start_time + timedelta(minutes=run_window_minutes)

def send_scan_notification(host_ips, os_label, batch_id=None):
    """Send email notification before scan starts"""
    try:
        # Email configuration from environment variables
        smtp_server = os.getenv("SMTP_SERVER", "localhost")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_username = os.getenv("SMTP_USERNAME", "")
        smtp_password = os.getenv("SMTP_PASSWORD", "")
        sender_email = os.getenv("SMTP_FROM_EMAIL", "noreply@example.com")
        recipient_emails = os.getenv("NOTIFICATION_EMAILS", "admin@example.com").split(",")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = ", ".join(recipient_emails)
        msg['Subject'] = f"Nessus Vulnerability Scan Starting - {os_label.upper()} Hosts"
        
        # Email body
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        host_list = "\n".join([f"  - {ip}" for ip in host_ips])
        
        body = f"""
Nessus Vulnerability Scan Notification

Scan Details:
- Start Time: {current_time}
- OS Type: {os_label.upper()}
- Number of Hosts: {len(host_ips)}
- Batch ID: {batch_id if batch_id else 'N/A'}

Hosts to be scanned:
{host_list}

This is an automated notification from the Nessus vulnerability scanning system.
The scan will begin shortly and you will receive updates upon completion.

Best regards,
Nessus Scanning System
"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email using TLS and authentication
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp_username, smtp_password)
        text = msg.as_string()
        server.sendmail(sender_email, recipient_emails, text)
        server.quit()
        
        print(f"Email notification sent successfully to {', '.join(recipient_emails)}")
        return True
        
    except Exception as e:
        print(f"Failed to send email notification: {e}")
        return False

def update_host_scan_dates(host_ips):
    """Update last_scan_date for the specified host IPs"""
    session = SessionLocal()
    try:
        current_time = datetime.utcnow()
        updated_count = 0
        
        for host_ip in host_ips:
            host = session.query(Host).filter(Host.host_ip == host_ip).first()
            if host:
                host.last_scan_date = current_time
                updated_count += 1
                print(f"Updated last_scan_date for host {host_ip} to {current_time}")
            else:
                print(f"Warning: Host with IP {host_ip} not found in database")
        
        session.commit()
        print(f"Successfully updated last_scan_date for {updated_count} hosts")
        return True
        
    except Exception as e:
        print(f"Error updating host scan dates: {e}")
        session.rollback()
        return False
    finally:
        session.close()

async def store_scan_data_after_completion():
    """
    Store scan data after completion by calling the API endpoint
    Waits 1 minute after scan completion before calling the API
    """
    scan_id = 5308  # or make this configurable if needed
    isinventoryscan = False
    
    try:
        print(f"🔍 DEBUG: store_scan_data_after_completion() called")
        print(f"Storing scan data for scan_id: {scan_id}, isinventoryscan: {isinventoryscan}")
       
        print("Scan is completed. Waiting 1 minute before calling API...")
        await asyncio.sleep(60)  # Wait 1 minute after completion
        
        # Call the API endpoint directly
        api_url = f"{Config.API_BASE_URL}/api/scans/{scan_id}?isinventoryscan={str(isinventoryscan).lower()}"
        access_token = os.getenv("API_ACCESS_TOKEN", "")
        
        if not access_token:
            print("API_ACCESS_TOKEN not available. Skipping scan data store.")
            return
            
        headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {access_token}"
        }
        
        print(f"Calling API endpoint: {api_url}")
        response = requests.get(api_url, headers=headers, verify=False)  # Ignore certificate
        print(f"API response status: {response.status_code}")
        
        if response.status_code == 200:
            print(f"Scan data stored successfully: {response.status_code}")
        else:
            print(f"Failed to store scan data: {response.status_code} {response.text}")
        
        print(f"🔍 DEBUG: store_scan_data_after_completion() completed successfully")
            
    except Exception as e:
        print(f"🔍 DEBUG: Exception in store_scan_data_after_completion(): {e}")
        print(f"Exception while storing scan data: {e}")
        import traceback
        traceback.print_exc()

def cleanup_on_exit():
    """Cleanup function to remove lock file on script exit"""
    remove_scan_lock()

if __name__ == "__main__":
    import atexit
    atexit.register(cleanup_on_exit)
    
    parser = argparse.ArgumentParser(description="Vuln Scan Batch Runner")
    parser.add_argument("--batch_size", type=int, default=2, help="Number of hosts to scan in a batch")
    parser.add_argument("--batch_id", type=int, default=None, help="Batch job ID")
    parser.add_argument("--clear_lock", action="store_true", help="Clear scan lock file and exit")
    parser.add_argument("--lock_status", action="store_true", help="Show scan lock status and exit")
    args = parser.parse_args()
    
    # Handle lock status option
    if args.lock_status:
        print("Checking scan lock status...")
        show_scan_lock_status()
        sys.exit(0)
    
    # Handle clear lock option
    if args.clear_lock:
        print("Clearing scan lock file...")
        if force_clear_scan_lock():
            print("Scan lock cleared successfully")
            sys.exit(0)
        else:
            print("Failed to clear scan lock")
            sys.exit(1)

    batch_size = args.batch_size
    batch_id = args.batch_id
    print(f"Starting vuln_scan.py with batch_id={batch_id} and batch_size={batch_size}")

    RUN_WINDOW_MINUTES = get_run_window_minutes(batch_id)

    start_time = datetime.now()
    current_os = read_scan_state()
    scan_in_progress = False

    while True:
        # Check if time to end script - but only if no scan is in progress
        if not scan_in_progress and is_time_to_end(start_time, RUN_WINDOW_MINUTES):
            print("Run window expired. Pushing scan data before exit.")
            asyncio.run(store_scan_data_after_completion())
            sys.exit(0)

        # Check if another scan is already running (both lock file and actual scan status)
        if is_scan_locked():
            print("Another scan is currently running (lock file exists). Waiting 60 seconds before checking again...")
            time.sleep(60)
            continue
        
        # Double-check with Nessus API if any scan is actually running
        try:
            get_api_token, token = get_nessus_token()
            if get_api_token and token:
                if is_scan_running(get_api_token, token):
                    print("A scan is currently running according to Nessus API. Waiting 60 seconds before checking again...")
                    time.sleep(60)
                    continue
        except Exception as e:
            print(f"Error checking scan status: {e}. Proceeding with caution...")

        print(f"Processing batch for OS: {current_os}")
        hosts = get_hosts_by_os(current_os, batch_size)
        if hosts:
            ips = ",".join([entry[0] for entry in hosts])
            # Determine the actual OS type from the hosts being scanned
            actual_os_types = set(entry[1] for entry in hosts if entry[1])
            if not actual_os_types:
                actual_os_types = {"unknown"}
            
            # Count OS types to determine the most common one
            os_counts = {}
            for entry in hosts:
                if entry[1]:  # if os_name is not None/empty
                    os_name = entry[1].lower()
                    if "windows" in os_name:
                        os_counts["windows"] = os_counts.get("windows", 0) + 1
                    elif "linux" in os_name:
                        os_counts["linux"] = os_counts.get("linux", 0) + 1
                    else:
                        os_counts["unknown"] = os_counts.get("unknown", 0) + 1
                else:
                    os_counts["unknown"] = os_counts.get("unknown", 0) + 1
            
            # Use the most common OS type, or default to the first one if all are equal
            if os_counts:
                actual_os_label = max(os_counts, key=os_counts.get)
            else:
                actual_os_label = "unknown"
                
            print(f"Launching scan for hosts with OS: {actual_os_label.capitalize()}, IPs: {ips}")
            print(f"OS distribution in this batch: {os_counts}")
            
            # Create scan lock before proceeding
            if not create_scan_lock(actual_os_label):
                print("Failed to create scan lock. Another scan might be starting. Skipping this batch.")
                next_os = get_next_os(current_os)
                write_scan_state(next_os)
                current_os = next_os
                continue
            
            get_api_token, token = get_nessus_token()
            
            if not get_api_token or not token:
                print("Failed to obtain Nessus authentication tokens. Removing lock and skipping this batch.")
                remove_scan_lock()
                # Update state for next run
                next_os = get_next_os(current_os)
                write_scan_state(next_os)
                current_os = next_os
                continue
            
            # Check if any scan is currently running and wait for completion
            print("Checking for existing scans before starting new one...")
            if not wait_for_existing_scan_completion(get_api_token, token):
                print("Could not wait for existing scan completion or scan is still running. Removing lock and skipping this batch.")
                remove_scan_lock()
                next_os = get_next_os(current_os)
                write_scan_state(next_os)
                current_os = next_os
                print("Waiting 5 minutes before trying next batch...")
                time.sleep(300)  # Wait 5 minutes before trying again
                continue
            
            # Send email notification only when we're about to start the scan
            host_ips_list = [entry[0] for entry in hosts]
            email_sent = send_scan_notification(host_ips_list, actual_os_label, batch_id)
            if email_sent:
                print("Pre-scan email notification sent successfully")
            else:
                print("Warning: Failed to send pre-scan email notification")
            
            # Mark scan as in progress
            scan_in_progress = True
            
            scan_launched = False
            try:
                if actual_os_label == 'windows':
                    scan_launched = update_and_launch_scan(get_api_token, token, ips, policy_id=3246, os_name_label="windows")
                elif actual_os_label == 'linux':
                    scan_launched = update_and_launch_scan(get_api_token, token, ips, policy_id=3231, os_name_label="linux")
                else:
                    scan_launched = update_and_launch_scan(get_api_token, token, ips, policy_id=5294, os_name_label="unknown")
            except Exception as e:
                print(f"Exception during scan launch for {actual_os_label}: {e}")
                scan_launched = False
            
            if scan_launched:
                # Update host scan dates immediately after successful launch
                host_ips_list = [entry[0] for entry in hosts]
                update_success = update_host_scan_dates(host_ips_list)
                
                if update_success:
                    print(f"Successfully updated scan dates for {len(host_ips_list)} hosts (scan started)")
                else:
                    print("Warning: Failed to update some host scan dates")
                
                # Note: Scan data will be stored after completion, not immediately after launch
                print("Scan launched successfully. Will store data after completion.")
                
                try:
                    # Wait for scan completion - this will block until scan is done
                    print(f"Waiting for {actual_os_label} scan to complete...")
                    scan_completed = wait_for_scan_completion(get_api_token, token)
                    
                    if scan_completed:
                        # Store scan data again after completion for final results
                        print("Storing final scan data after completion...")
                        asyncio.run(store_scan_data_after_completion())
                        print(f"Scan completed successfully for {actual_os_label} hosts.")
                        
                        # Reset ready_for_rescan toggles for scanned hosts
                        reset_ready_for_rescan_toggles(host_ips_list)
                        
                        # Remove lock only after successful completion
                        remove_scan_lock()
                        print("Scan lock removed after successful completion.")
                        
                        print("Waiting 4 minutes before proceeding to next batch...")
                        time.sleep(240)  # Wait 4 minutes
                    else:
                        print(f"Scan did not complete for {actual_os_label} hosts.")
                        print("Note: Host scan dates and initial scan data were already stored when scan started.")
                        print("Keeping lock file to prevent new scans until this one is resolved.")
                        # Don't remove lock if scan didn't complete - this prevents new scans
                        print("Waiting 10 minutes before checking scan status again...")
                        time.sleep(600)  # Wait 10 minutes before checking again
                    
                except Exception as e:
                    print(f"Exception during scan completion for {actual_os_label}: {e}")
                    print("Note: Host scan dates and initial scan data were already stored when scan started.")
                    print("Keeping lock file to prevent new scans due to exception.")
                    # Don't remove lock on exception - this prevents new scans
                    print("Waiting 10 minutes before checking scan status again...")
                    time.sleep(600)  # Wait 10 minutes before checking again
            else:
                print(f"Failed to launch scan for {actual_os_label} hosts. Moving to next OS type.")
                # Remove lock on scan failure
                remove_scan_lock()
            
            # Mark scan as completed
            scan_in_progress = False
            
            # Check if time window expired after scan completion
            if is_time_to_end(start_time, RUN_WINDOW_MINUTES):
                print("Run window expired after scan completion. Pushing scan data before exit.")
                asyncio.run(store_scan_data_after_completion())
                sys.exit(0)
        else:
            print(f"No {current_os.capitalize()} hosts to scan in this batch.")
            # Check if time window expired when no hosts to scan
            if is_time_to_end(start_time, RUN_WINDOW_MINUTES):
                print("Run window expired. Pushing scan data before exit.")
                asyncio.run(store_scan_data_after_completion())
                sys.exit(0)
        
        # Update state for next run
        next_os = get_next_os(current_os)
        write_scan_state(next_os)
        current_os = next_os
        
        # Add a small delay between OS types to prevent overwhelming the server
        time.sleep(10)

async def start_immediate_scan_for_hosts(host_ips: list[str], scan_type: str = "ready_hosts_rescan"):
    """Start an immediate scan for ready hosts with full scan process"""
    try:
        logger.info(f"🚀 Starting immediate scan for {len(host_ips)} ready hosts")
        
        # Get hosts by IPs
        session = SessionLocal()
        try:
            hosts = session.query(Host).filter(Host.host_ip.in_(host_ips)).all()
            if not hosts:
                raise ValueError("No hosts found for the provided IPs")
            
            # Reset ready_for_rescan flags for these hosts
            reset_ready_for_rescan_toggles(host_ips)
            
        finally:
            session.close()
        
        # Get Nessus authentication token
        get_api_token, token = get_nessus_token()
        if not get_api_token or not token:
            raise ValueError("Failed to get Nessus authentication token")
        
        # Check if any scan is currently running and wait for completion
        logger.info("Checking for existing scans before starting immediate scan...")
        if not wait_for_existing_scan_completion(get_api_token, token):
            logger.warning("Could not wait for existing scan completion or scan is still running. Skipping immediate scan.")
            return {
                "scan_id": None,
                "host_count": len(host_ips),
                "scan_type": scan_type,
                "status": "skipped",
                "message": "Another scan is currently running. Immediate scan skipped."
            }
        
        # Prepare IPs for scanning
        ips = ",".join(host_ips)
        
        # Send email notification
        email_sent = send_scan_notification(host_ips, "immediate", f"immediate_{int(time.time())}")
        if email_sent:
            logger.info("Pre-scan email notification sent successfully")
        else:
            logger.warning("Failed to send pre-scan email notification")
        
        # Launch scan using unknown policy (5294) for immediate scans
        logger.info("Launching immediate scan with unknown policy...")
        scan_launched = update_and_launch_scan(get_api_token, token, ips, policy_id=5294, os_name_label="unknown")
        
        if not scan_launched:
            raise ValueError("Failed to launch immediate scan")
        
        # Update host scan dates immediately after successful launch
        update_success = update_host_scan_dates(host_ips)
        if update_success:
            logger.info(f"Successfully updated scan dates for {len(host_ips)} hosts (immediate scan started)")
        else:
            logger.warning("Failed to update some host scan dates")
        
        # Note: Scan data will be stored after completion, not immediately after launch
        logger.info("Immediate scan launched successfully. Will store data after completion.")
        
        # Start monitoring the scan completion in background
        asyncio.create_task(monitor_immediate_scan_completion(host_ips, get_api_token, token))
        
        scan_id = f"immediate_{int(time.time())}"
        logger.info(f"Immediate scan launched successfully for {len(host_ips)} hosts: {host_ips}")
        
        return {
            "scan_id": scan_id,
            "host_count": len(host_ips),
            "scan_type": scan_type,
            "status": "launched",
            "message": f"Immediate scan launched successfully for {len(host_ips)} hosts using unknown policy."
        }
            
    except Exception as e:
        logger.error(f"❌ Error starting immediate scan: {e}")
        return {
            "scan_id": None,
            "host_count": len(host_ips) if 'host_ips' in locals() else 0,
            "scan_type": scan_type,
            "status": "error",
            "message": f"Failed to start immediate scan: {str(e)}"
        }


async def monitor_immediate_scan_completion(host_ips: list[str], get_api_token: str, token: str):
    """Monitor immediate scan completion and store results"""
    try:
        logger.info(f"🔍 Starting to monitor immediate scan completion for {len(host_ips)} hosts")
        
        # Wait for scan to complete (check every 30 seconds)
        max_wait_time = 3600  # 1 hour max wait
        check_interval = 30   # 30 seconds
        elapsed_time = 0
        
        # Current tokens (will be refreshed if needed)
        current_get_api_token = get_api_token
        current_token = token
        
        while elapsed_time < max_wait_time:
            try:
                # Check if scan is still running
                nessus_config = get_nessus_config()
                if not nessus_config:
                    logger.error("Failed to get Nessus configuration for scan monitoring")
                    break
                
                server_url = nessus_config["server_url"].rstrip('/')
                scan_status_url = f"{server_url}/scans/5308"
                headers = {
                    "X-Api-Token": current_get_api_token,
                    "content-type": "application/json",
                    "X-Cookie": f"token={current_token}"
                }
                
                response = requests.get(scan_status_url, headers=headers, verify=False)
                
                if response.status_code == 200:
                    scan_data = response.json()
                    scan_status = scan_data.get("info", {}).get("status", "unknown")
                    
                    if scan_status == "completed":
                        logger.info("✅ Immediate scan completed successfully!")
                        
                        # Store scan results
                        logger.info("Storing immediate scan results...")
                        try:
                            await store_scan_data_after_completion()
                            logger.info("✅ Scan data storage completed successfully")
                        except Exception as e:
                            logger.error(f"❌ Error storing scan data: {e}")
                            import traceback
                            logger.error(f"Traceback: {traceback.format_exc()}")
                        
                        # Send completion notification
                        send_scan_notification(host_ips, "immediate_completed", f"immediate_{int(time.time())}")
                        
                        logger.info(f"Immediate scan monitoring completed for {len(host_ips)} hosts")
                        break
                    elif scan_status == "failed" or scan_status == "canceled":
                        logger.error(f"❌ Immediate scan {scan_status}")
                        break
                    else:
                        logger.info(f"⏳ Immediate scan still running (status: {scan_status})")
                        
                elif response.status_code == 401:
                    logger.warning("Authentication failed during scan monitoring. Attempting to refresh token...")
                    try:
                        new_get_api_token, new_token = get_nessus_token()
                        if new_get_api_token and new_token:
                            current_get_api_token = new_get_api_token
                            current_token = new_token
                            logger.info("Token refreshed for scan monitoring. Continuing...")
                            continue
                        else:
                            logger.error("Failed to refresh token for scan monitoring.")
                            break
                    except Exception as e:
                        logger.error(f"Error refreshing token for scan monitoring: {e}")
                        break
                else:
                    logger.warning(f"Failed to check scan status: {response.status_code}")
                    
            except Exception as e:
                logger.error(f"Error checking scan status: {e}")
            
            # Wait before next check
            await asyncio.sleep(check_interval)
            elapsed_time += check_interval
            
        if elapsed_time >= max_wait_time:
            logger.warning("⏰ Immediate scan monitoring timed out after 1 hour")
            
    except Exception as e:
        logger.error(f"❌ Error monitoring immediate scan completion: {e}")
from typing import Any, Dict
import requests
from services.db import store_scan_results_auto
import pandas as pd
from io import StringIO
import time
import urllib3
import psutil
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Suppress SSL warnings for Nessus API calls
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Nessus_API_URL = os.getenv("NESSUS_API_URL", "https://nessus.example.com:8834")
ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY", "")
SECRET_KEY = os.getenv("NESSUS_SECRET_KEY", "")

# Configuration for large dataset handling
def get_memory_limits():
    """Dynamically calculate memory limits based on system resources"""
    import os
    total_memory_gb = psutil.virtual_memory().total / (1024**3)
    available_memory_gb = psutil.virtual_memory().available / (1024**3)

    # Allow override via environment variables
    max_memory_override = os.getenv('NESSUS_MAX_MEMORY_GB')
    max_csv_override = os.getenv('NESSUS_MAX_CSV_MB')
    allow_high_memory = os.getenv('NESSUS_ALLOW_HIGH_MEMORY', 'false').lower() == 'true'

    if max_memory_override:
        max_memory_limit = float(max_memory_override)
        print(f"Using memory limit override: {max_memory_limit} GB")
    else:
        # Use 80% of total memory as the absolute limit, but not more than 90% of available memory
        max_memory_limit = min(total_memory_gb * 0.8, available_memory_gb * 0.9)
        # Ensure minimum limits
        max_memory_limit = max(max_memory_limit, 4.0)  # At least 4GB

    if max_csv_override:
        max_csv_limit = int(max_csv_override)
        print(f"Using CSV size limit override: {max_csv_limit} MB")
    else:
        max_csv_limit = 10000  # 10GB - effectively no limit for large scans

    return {
        'max_memory_usage_gb': max_memory_limit,
        'max_csv_size_mb': max_csv_limit,
        'chunk_size_default': 5000,
        'allow_high_memory': allow_high_memory,
    }

# Get dynamic limits
MEMORY_CONFIG = get_memory_limits()
MAX_MEMORY_USAGE_GB = MEMORY_CONFIG['max_memory_usage_gb']
MAX_CSV_SIZE_MB = MEMORY_CONFIG['max_csv_size_mb']
CHUNK_SIZE_DEFAULT = MEMORY_CONFIG['chunk_size_default']
ALLOW_HIGH_MEMORY = MEMORY_CONFIG['allow_high_memory']

print(f"Memory limits configured: Max {MAX_MEMORY_USAGE_GB:.1f} GB usage, CSV files unlimited, High memory mode: automatic when needed")

session = requests.Session()
session.headers.update({
    "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}",
    "Content-Type": "application/json"
})

def get_system_memory_gb():
    """Get current system memory usage in GB"""
    return psutil.virtual_memory().used / (1024**3)

def should_use_conservative_mode(csv_size_mb: float) -> bool:
    """Determine if conservative processing mode should be used"""
    memory_usage = get_system_memory_gb()
    available_memory = psutil.virtual_memory().available / (1024**3)

    # Use conservative mode if:
    # - CSV is very large (>200MB)
    # - Memory usage is high (>70% of total memory)
    # - Available memory is low (<20% of total memory)
    total_memory = psutil.virtual_memory().total / (1024**3)
    memory_usage_percent = (memory_usage / total_memory) * 100
    available_percent = (available_memory / total_memory) * 100

    conservative = (
        csv_size_mb > 200 or
        memory_usage_percent > 70 or
        available_percent < 20
    )

    if conservative:
        print(f"Using conservative mode: CSV={csv_size_mb:.1f}MB, Memory={memory_usage_percent:.1f}%, Available={available_percent:.1f}%")

    return conservative

def export_scan_csv(scan_id, timeout_minutes=10):
    """
    Export scan to CSV with extended timeout for large scans
    """
    url = f'{Nessus_API_URL}/scans/{scan_id}/export'
    response = session.post(url, json={"format": "csv"}, verify=False, timeout=60)
    if response.status_code == 200:
        file_id = response.json()['file']
        print(f"Export initiated for scan {scan_id}, file ID: {file_id}")

        # Poll for export status with extended timeout for large scans
        status_url = f'{Nessus_API_URL}/scans/{scan_id}/export/{file_id}/status'
        max_attempts = timeout_minutes * 60 // 5  # Check every 5 seconds
        attempt = 0

        while attempt < max_attempts:
            attempt += 1
            try:
                status_resp = session.get(status_url, verify=False, timeout=30)
                if status_resp.status_code == 200:
                    status_data = status_resp.json()
                    current_status = status_data.get("status")

                    if current_status == "ready":
                        print(f"Export ready after {attempt * 5} seconds")
                        return file_id
                    elif current_status == "error":
                        print(f"Export failed with error status")
                        return None
                    else:
                        # Still processing
                        if attempt % 12 == 0:  # Log every minute
                            print(f"Export still processing... ({attempt * 5}s elapsed)")
                else:
                    print(f"Status check failed: HTTP {status_resp.status_code}")
                    return None
            except Exception as e:
                print(f"Error checking export status: {e}")
                return None

            time.sleep(5)

        print(f'Export not ready after {timeout_minutes} minutes. Giving up.')
        return None
    else:
        print(f'Error exporting findings: {response.status_code} - {response.text}')
        return None

def download_scan_csv(scan_id, file_id, chunk_size=8192):
    """
    Download scan CSV with streaming and optional temporary file storage for large files
    """
    import tempfile
    import os

    download_url = f'{Nessus_API_URL}/scans/{scan_id}/export/{file_id}/download'

    try:
        # First, get the content length if available
        head_response = session.head(download_url, verify=False, timeout=30)
        expected_size = None
        use_temp_file = False
        temp_file_path = None

        if head_response.status_code == 200 and 'content-length' in head_response.headers:
            expected_size = int(head_response.headers['content-length'])
            expected_size_mb = expected_size / (1024 * 1024)
            print(f"Expected file size: {expected_size_mb:.1f} MB")

        # Use streaming download for large files
        with session.get(download_url, verify=False, timeout=300, stream=True) as download_response:
            if download_response.status_code == 200:
                print(f"Starting download of scan {scan_id} CSV...")

                # Read in chunks to handle large files
                total_size = 0
                memory_warnings = 0
                csv_content = []
                temp_file = None

                for chunk in download_response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        # Check if we should switch to temp file storage
                        memory_usage = get_system_memory_gb()
                        if not use_temp_file and (memory_usage > MAX_MEMORY_USAGE_GB * 0.7 or len(csv_content) > 1000):  # 70% of limit or too many chunks
                            # Switch to temporary file storage
                            use_temp_file = True
                            temp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.csv')
                            temp_file_path = temp_file.name
                            print(f"Switching to temporary file storage: {temp_file_path}")

                            # Write existing content to temp file
                            for existing_chunk in csv_content:
                                temp_file.write(existing_chunk)
                            csv_content = []  # Clear memory

                        if use_temp_file:
                            temp_file.write(chunk)
                        else:
                            csv_content.append(chunk)

                        total_size += len(chunk)

                        # Check memory usage during download (less frequently for performance)
                        if total_size > 50 * 1024 * 1024:  # Check every 50MB
                            memory_usage = get_system_memory_gb()
                            if memory_usage > MAX_MEMORY_USAGE_GB:
                                # Automatically allow high memory usage when needed
                                print(f"Warning: High memory usage ({memory_usage:.1f} GB > {MAX_MEMORY_USAGE_GB:.1f} GB limit), automatically enabling high memory mode to continue processing")
                                # Continue processing - no longer abort

                        # Log progress for large files
                        if total_size > 10 * 1024 * 1024:  # 10MB
                            size_mb = total_size / (1024*1024)
                            print(f"Downloaded {size_mb:.1f} MB...")

                # Close temp file if used
                if temp_file:
                    temp_file.close()

                csv_data = None
                final_size_mb = total_size / (1024*1024)
                print(f"Download complete: {final_size_mb:.1f} MB")

                # Return appropriate data structure
                if use_temp_file:
                    print(f"Using temporary file for processing: {temp_file_path}")
                    return temp_file_path  # Return file path instead of data
                else:
                    csv_data = b''.join(csv_content).decode('utf-8', errors='replace')
                    return csv_data

            else:
                print(f'Error downloading findings: HTTP {download_response.status_code}')
                if download_response.status_code == 404:
                    print("Scan export not found - it may have expired or been deleted")
                return None
    except MemoryError:
        print("Memory error during download - system ran out of memory")
        if temp_file_path and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
        return None
    except Exception as e:
        print(f'Error during download: {e}')
        if temp_file_path and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
        return None

def convert_csv_to_json(csv_data_or_path, chunk_size=5000):
    """
    Convert CSV to JSON with chunked processing for large datasets
    Supports both in-memory CSV data (string) and temporary file paths
    """
    import os

    try:
        # Determine if input is a file path or CSV data
        is_file_path = isinstance(csv_data_or_path, str) and os.path.isfile(csv_data_or_path)

        if is_file_path:
            print(f"Reading CSV from temporary file: {csv_data_or_path}")
            # Get file size for memory calculations
            file_size = os.path.getsize(csv_data_or_path)
            csv_size_mb = file_size / (1024 * 1024)
            print(f"Temporary file size: {csv_size_mb:.1f} MB")

            # Use pandas to read directly from file
            df = pd.read_csv(csv_data_or_path, low_memory=False)

            # Clean up the temporary file immediately after reading
            try:
                os.unlink(csv_data_or_path)
                print(f"Cleaned up temporary file: {csv_data_or_path}")
            except Exception as e:
                print(f"Warning: Could not clean up temporary file {csv_data_or_path}: {e}")

        else:
            # Original in-memory processing
            csv_data = csv_data_or_path
            if not csv_data or not csv_data.strip():
                return []

            csv_size_mb = len(csv_data) / (1024 * 1024)
            use_conservative = should_use_conservative_mode(csv_size_mb)

            if use_conservative:
                print(f"Using conservative processing mode for {csv_size_mb:.1f} MB CSV")
                chunk_size = max(1000, chunk_size // 2)  # Smaller chunks for conservative mode

            # Use pandas with memory-efficient settings for large files
            df = pd.read_csv(StringIO(csv_data), low_memory=False)

        # Remove duplicates early to reduce memory usage
        if len(df) > 1000:
            print(f"Removing duplicates from {len(df)} records...")
            df = df.drop_duplicates(subset=['Host', 'Description', 'Solution'])
            print(f"After deduplication: {len(df)} records")

        # Check memory usage after loading
        memory_after_load = get_system_memory_gb()
        if memory_after_load > MAX_MEMORY_USAGE_GB:
            print(f"Warning: High memory usage after loading CSV ({memory_after_load:.1f} GB > {MAX_MEMORY_USAGE_GB:.1f} GB), automatically enabling high memory mode to continue processing")
            # Continue processing - no longer abort

        # Replace NaN with None
        df = df.where(pd.notnull(df), None)

        # Process in chunks for very large datasets
        if len(df) > chunk_size:
            print(f"Processing dataset ({len(df)} records) in chunks of {chunk_size}...")
            all_records = []

            for start_idx in range(0, len(df), chunk_size):
                end_idx = min(start_idx + chunk_size, len(df))
                chunk_df = df.iloc[start_idx:end_idx]

                chunk_records = chunk_df.to_dict(orient='records')

                # Clean up NaN values in this chunk
                for rec in chunk_records:
                    for k, v in rec.items():
                        if isinstance(v, float) and pd.isna(v):
                            rec[k] = None

                all_records.extend(chunk_records)

                # Check memory usage during processing
                if len(all_records) % 10000 == 0:  # Check every 10k records
                    memory_usage = get_system_memory_gb()
                    if memory_usage > MAX_MEMORY_USAGE_GB:
                        print(f"Warning: High memory usage during processing ({memory_usage:.1f} GB > {MAX_MEMORY_USAGE_GB:.1f} GB), automatically enabling high memory mode to continue processing")
                        # Continue processing - no longer abort

                print(f"Processed chunk {start_idx//chunk_size + 1}/{(len(df) + chunk_size - 1)//chunk_size}")

            return all_records
        else:
            # Standard processing for smaller datasets
            records = df.to_dict(orient='records')
            for rec in records:
                for k, v in rec.items():
                    if isinstance(v, float) and pd.isna(v):
                        rec[k] = None
            return records

    except pd.errors.EmptyDataError:
        return []
    except Exception as e:
        print(f"Error converting CSV to JSON: {e}")
        return []

async def fetch_scan_details(scan_id: str, isinventoryscan: bool) -> Dict[str, Any]:
    """
    Fetch scan details with optimized handling for large datasets
    """
    try:
        print(f"Starting scan details fetch for scan ID: {scan_id}")

        # Step 1: Export scan to CSV (with extended timeout for large scans)
        print("Step 1: Exporting scan to CSV...")
        file_id = export_scan_csv(scan_id, timeout_minutes=15)  # 15 minutes for large scans
        if not file_id:
            print("Failed to export scan - this may be due to scan size or server issues")
            return []

        # Step 2: Download CSV with streaming
        print("Step 2: Downloading CSV data...")
        findings_csv = download_scan_csv(scan_id, file_id)
        if not findings_csv:
            print("Failed to download CSV data")
            return []

        # Step 3: Convert CSV to JSON with chunked processing
        print("Step 3: Converting CSV to JSON...")
        findings_json = convert_csv_to_json(findings_csv)

        if not findings_json:
            print("No findings data found in scan")
            return []

        print(f"Successfully processed {len(findings_json):,} findings")

        # Step 4: Store results using auto-selection for optimal performance
        print("Step 4: Storing scan results in database...")
        scan_data = {"scan_details": findings_json}
        store_scan_results_auto(scan_data, isinventoryscan)

        print(f"Scan {scan_id} processing completed successfully")
        return findings_json

    except MemoryError:
        print("Memory error occurred while processing scan - dataset may be too large")
        return []
    except Exception as e:
        print(f"Error fetching scan details for {scan_id}: {e}")
        return []

def fetch_running_scans():
    try:
        url = f"{Nessus_API_URL}/scans"
        resp = session.get(url, verify=False, timeout=10)
        resp.raise_for_status()
        scans = resp.json().get("scans", [])
        running = [scan for scan in scans if scan.get("status") == "running"]
        return running
    except Exception as e:
        print(f"Error fetching running scans: {e}")
        return None

    
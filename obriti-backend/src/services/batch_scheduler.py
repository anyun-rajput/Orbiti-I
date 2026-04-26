import time
import schedule
from sqlalchemy.orm import Session
from services.db import SessionLocal
from models.scan import BatchScan
from datetime import datetime
import subprocess
import threading
import traceback
import os
import pytz

def run_scan(batch_id, batch_name, batch_size, batch_job):
    print(f"run_scan called for batch_id={batch_id} at {datetime.now()}")
    if batch_job.lower() == "vuln_scan":
        try:
            print(f"Launching vuln_scan.py for batch_id={batch_id}, batch_name={batch_name}, batch_size={batch_size}")
            script_path = os.path.abspath("/app/src/services/vuln_scan.py")
            with open("vuln_scan.log", "a") as f:
                subprocess.Popen(
                    ["python", script_path, "--batch_id", str(batch_id), "--batch_size", str(batch_size)],
                    cwd=".",
                    stdout=f,
                    stderr=subprocess.STDOUT,
                )
        except Exception as e:
            print("Error launching vuln_scan.py:", e)
            traceback.print_exc()
    else:
        print(f"Unknown or unsupported batch_job: {batch_job}")

def to_24h(time_str, timezone_str="Asia/Kolkata"):
    # Converts various time formats to 24-hour format in specified timezone
    time_str = time_str.strip()
    
    # Try different formats
    formats_to_try = [
        "%I:%M %p",  # 08:30 AM
        "%I:%M%p",   # 08:30AM
        "%H:%M",     # 08:30 (24-hour)
        "%I:%M",     # 08:30 (12-hour without AM/PM)
    ]
    
    for fmt in formats_to_try:
        try:
            dt = datetime.strptime(time_str, fmt)
            # If format doesn't include AM/PM, assume it's already 24-hour
            if fmt in ["%H:%M", "%I:%M"]:
                return time_str
            
            # Convert to 24-hour format
            return dt.strftime("%H:%M")
        except ValueError:
            continue
    
    # If all formats fail, raise a clear error
    raise ValueError(f"Time data '{time_str}' does not match any expected format. "
                   f"Expected formats: '08:30 AM', '08:30AM', '08:30', or '20:30'")

def convert_to_kolkata_time(time_str, timezone_str="Asia/Kolkata"):
    """
    Parse IST time and return in 24-hour format for scheduling
    Since user provides IST times, we keep them as-is for scheduling
    """
    try:
        # Parse the time string
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
        
        # Return the time in 24-hour format as-is
        # The schedule will run at this local time
        return dt.strftime("%H:%M")
        
    except Exception as e:
        print(f"Error parsing time: {e}")
        # Fallback to original time parsing
        return to_24h(time_str)

# Persistent job registry
scheduled_jobs = {}
scheduler_lock = threading.Lock()

def schedule_job(batch):
    week_day = batch.week_day
    job_start_time = batch.job_start_time
    # Handle ranges like '2-5'
    days = []
    if '-' in week_day:
        start, end = map(int, week_day.split('-'))
        days = list(range(start, end + 1))
    else:
        days = [int(week_day)]
    # Map 0-6 to schedule methods
    schedule_methods = [
        schedule.every().monday,
        schedule.every().tuesday,
        schedule.every().wednesday,
        schedule.every().thursday,
        schedule.every().friday,
        schedule.every().saturday,
        schedule.every().sunday,
    ]
    job_refs = []
    for d in days:
        d_index = d - 1  # Adjust for 1-based input
        # Convert time to Kolkata timezone for scheduling
        job_start_time_24h = convert_to_kolkata_time(job_start_time)
        print(f"Scheduling job: {batch.batch_name} on day {d_index} at {job_start_time_24h} (Kolkata time)")
        if not (0 <= d_index < len(schedule_methods)):
            print(f"Invalid week_day index: {d_index}")
            continue
        job_ref = schedule_methods[d_index].at(job_start_time_24h).do(
            run_scan, batch.id, batch.batch_name, batch.batch_size, batch.batch_job
        )
        job_refs.append(job_ref)
    return job_refs

def reschedule_all_jobs():
    global scheduled_jobs
    with scheduler_lock:
        # Cancel all current jobs
        for job_list in scheduled_jobs.values():
            for job_ref in job_list:
                schedule.cancel_job(job_ref)
        scheduled_jobs.clear()
        # Fetch all current batch jobs from DB and reschedule
        session: Session = SessionLocal()
        try:
            db_batches = {b.id: b for b in session.query(BatchScan).all()}
            print(f"Rescheduling jobs. Found {len(db_batches)} jobs in DB.")
        finally:
            session.close()
        for batch_id, batch in db_batches.items():
            scheduled_jobs[batch_id] = schedule_job(batch)

def schedule_batch_scans():
    # Used by the background loop to ensure jobs are scheduled at startup
    reschedule_all_jobs()

if __name__ == "__main__":
    schedule_batch_scans()
    while True:
        schedule.run_pending()
        time.sleep(30)
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.scan import router as scan_router, auth_router
from api.hosts import router as hosts_router  # <-- Add this import
from api.vuln import router as vuln_router  # <-- Add this import
from api.batch_scan import router as batch_scan_router  # <-- Add this import
import threading
from services.batch_scheduler import schedule_batch_scans, reschedule_all_jobs
import schedule
import time
from api.closed_vulnerabilities import router as closed_vuln_router

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000"],  # Or ["*"] for all origins (not recommended for production)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/api")
app.include_router(auth_router, prefix="/api/auth")
app.include_router(hosts_router, prefix="/api")  # <-- Add this line
app.include_router(vuln_router, prefix="/api")  # <-- Add this line
app.include_router(batch_scan_router, prefix="/api")  # <-- Add this line
app.include_router(closed_vuln_router, prefix="/api")

@app.on_event("startup")
def start_scheduler():
    def scheduler_loop():
        print("Scheduler loop started")
        schedule_batch_scans()
        while True:
            schedule.run_pending()
            time.sleep(15)
    t = threading.Thread(target=scheduler_loop, daemon=True)
    t.start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
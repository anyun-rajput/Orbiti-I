from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.db import SessionLocal
from models.scan import BatchScan
from services.batch_scheduler import reschedule_all_jobs
from datetime import datetime
from api.scan import get_current_user, require_permission
router = APIRouter(dependencies=[Depends(require_permission("scan_management"))])

class BatchScanRequest(BaseModel):
    batch_name: str
    batch_size: int
    batch_job: str  # 'vuln scan' or 'compliance scan'
    job_start_time: str  # e.g., '08:30 AM' (interpreted in Asia/Kolkata timezone)
    job_end_time: str    # e.g., '02:30 PM' (interpreted in Asia/Kolkata timezone)
    week_day: str        # e.g., '2-5' (1=Monday, 2=Tuesday, ..., 7=Sunday)

@router.post("/batch-scan/schedule")
async def schedule_batch_scan(request: BatchScanRequest):
    if request.batch_size <= 0:
        raise HTTPException(status_code=400, detail="Batch size must be positive.")

    session: Session = SessionLocal()
    try:
        batch_scan = BatchScan(
            batch_name=request.batch_name,
            batch_size=request.batch_size,
            batch_job=request.batch_job,
            job_start_time=request.job_start_time,
            job_end_time=request.job_end_time,
            week_day=request.week_day
        )
        session.add(batch_scan)
        session.commit()
        # After commit, reschedule all jobs
        reschedule_all_jobs()
        print(datetime.now())
        return {
            "message": f"Scheduled {request.batch_job} for batch '{request.batch_name}' with batch size {request.batch_size} on {request.week_day} from {request.job_start_time} to {request.job_end_time} (Asia/Kolkata timezone)",
            "batch_scan_id": batch_scan.id
        }
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.get("/batch-scan/all")
def get_all_batch_scans():
    session: Session = SessionLocal()
    try:
        batches = session.query(BatchScan).all()
        result = []
        for batch in batches:
            result.append({
                "id": batch.id,
                "batch_name": batch.batch_name,
                "batch_size": batch.batch_size,
                "batch_job": batch.batch_job,
                "job_start_time": batch.job_start_time,
                "job_end_time": batch.job_end_time,
                "week_day": batch.week_day,
                "created_at": batch.created_at.isoformat() if batch.created_at else None
            })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.delete("/batch-scan/{batch_id}")
async def delete_batch_scan(batch_id: int):
    """
    Delete a batch scan by ID.
    This will remove the batch from the database and cancel any scheduled jobs.
    """
    session: Session = SessionLocal()
    try:
        # Check if batch exists
        batch = session.query(BatchScan).filter(BatchScan.id == batch_id).first()
        if not batch:
            raise HTTPException(status_code=404, detail=f"Batch scan with ID {batch_id} not found")
        
        # Store batch info for response
        batch_name = batch.batch_name
        
        # Delete the batch from database
        session.delete(batch)
        session.commit()
        
        # Reschedule all jobs to remove the deleted batch from scheduler
        reschedule_all_jobs()
        
        return {
            "message": f"Batch scan '{batch_name}' (ID: {batch_id}) deleted successfully",
            "deleted_batch_id": batch_id,
            "deleted_batch_name": batch_name
        }
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting batch scan: {str(e)}")
    finally:
        session.close()
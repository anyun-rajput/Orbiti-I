from fastapi import APIRouter, Query, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc
from services.db import SessionLocal
from models.vuln import VulnerabilityException, Vulnerability, Host, host_vulnerability
from api.scan import get_current_user
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, date, timedelta
import uuid

router = APIRouter(dependencies=[Depends(get_current_user)])

# Pydantic models for request/response
class ExceptionCreateRequest(BaseModel):
    exception_id: str = Field(..., description="Unique exception identifier")
    vulnerability_id: Optional[int] = Field(None, description="Vulnerability ID (null for host-specific exceptions)")
    host_id: Optional[int] = Field(None, description="Host ID (null for vulnerability-specific exceptions)")
    exception_type: str = Field(..., description="Type of exception: vulnerability, host, or vulnerability_host")
    reason: str = Field(..., description="Reason for the exception")
    expiry_date: date = Field(..., description="Date when the exception expires")
    created_by: str = Field(..., description="User creating the exception")

class ExceptionUpdateRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Updated reason for the exception")
    expiry_date: Optional[date] = Field(None, description="Updated expiry date")
    is_active: Optional[bool] = Field(None, description="Whether the exception is active")

class ExceptionResponse(BaseModel):
    id: int
    exception_id: str
    vulnerability_id: Optional[int]
    host_id: Optional[int]
    exception_type: str
    reason: str
    expiry_date: str
    created_by: str
    created_at: str
    updated_at: str
    is_active: bool
    is_expired: bool
    vulnerability_name: Optional[str] = None
    hostname: Optional[str] = None
    host_ip: Optional[str] = None

@router.post("/exceptions", response_model=ExceptionResponse)
def create_exception(exception_data: ExceptionCreateRequest):
    """Create a new vulnerability exception"""
    session: Session = SessionLocal()
    try:
        # Validate exception type and required fields
        if exception_data.exception_type == "vulnerability" and not exception_data.vulnerability_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="vulnerability_id is required for vulnerability-type exceptions"
            )
        elif exception_data.exception_type == "host" and not exception_data.host_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="host_id is required for host-type exceptions"
            )
        elif exception_data.exception_type == "vulnerability_host" and (not exception_data.vulnerability_id or not exception_data.host_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Both vulnerability_id and host_id are required for vulnerability_host-type exceptions"
            )
        
        # Check if exception_id already exists
        existing = session.query(VulnerabilityException).filter(
            VulnerabilityException.exception_id == exception_data.exception_id
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Exception ID already exists"
            )
        
        # Validate vulnerability exists (if provided)
        if exception_data.vulnerability_id:
            vuln = session.query(Vulnerability).filter(
                Vulnerability.pluginid == exception_data.vulnerability_id
            ).first()
            if not vuln:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Vulnerability not found"
                )
        
        # Validate host exists (if provided)
        if exception_data.host_id:
            host = session.query(Host).filter(Host.id == exception_data.host_id).first()
            if not host:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Host not found"
                )
        
        # Create the exception
        exception = VulnerabilityException(
            exception_id=exception_data.exception_id,
            vulnerability_id=exception_data.vulnerability_id,
            host_id=exception_data.host_id,
            exception_type=exception_data.exception_type,
            reason=exception_data.reason,
            expiry_date=exception_data.expiry_date,
            created_by=exception_data.created_by
        )
        
        session.add(exception)
        session.commit()
        session.refresh(exception)
        
        # Get related data for response
        response_data = exception.to_dict()
        if exception.vulnerability:
            response_data["vulnerability_name"] = exception.vulnerability.pluginname
        if exception.host:
            response_data["hostname"] = exception.host.hostname
            response_data["host_ip"] = exception.host.host_ip
        
        return ExceptionResponse(**response_data)
        
    except HTTPException:
        session.rollback()
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create exception: {str(e)}"
        )
    finally:
        session.close()

class PaginatedExceptionResponse(BaseModel):
    exceptions: List[ExceptionResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

@router.get("/exceptions", response_model=PaginatedExceptionResponse)
def get_exceptions(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str = Query("", alias="search"),
    exception_type: str = Query("all", alias="exception_type"),
    is_active: Optional[bool] = Query(None, alias="is_active"),
    is_expired: Optional[bool] = Query(None, alias="is_expired")
):
    """Get list of vulnerability exceptions with filtering and pagination"""
    session: Session = SessionLocal()
    try:
        query = session.query(VulnerabilityException)
        
        # Apply filters
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    VulnerabilityException.exception_id.ilike(search_term),
                    VulnerabilityException.reason.ilike(search_term),
                    VulnerabilityException.created_by.ilike(search_term)
                )
            )
        
        if exception_type != "all":
            query = query.filter(VulnerabilityException.exception_type == exception_type)
        
        if is_active is not None:
            query = query.filter(VulnerabilityException.is_active == is_active)
        
        if is_expired is not None:
            current_date = date.today()
            if is_expired:
                query = query.filter(VulnerabilityException.expiry_date < current_date)
            else:
                query = query.filter(VulnerabilityException.expiry_date >= current_date)
        
        # Get total count
        total = query.count()
        
        # Calculate total pages
        total_pages = (total + page_size - 1) // page_size
        
        # Apply pagination
        exceptions = query.order_by(desc(VulnerabilityException.created_at)).offset(
            (page - 1) * page_size
        ).limit(page_size).all()
        
        # Build response data
        response_data = []
        for exception in exceptions:
            data = exception.to_dict()
            if exception.vulnerability:
                data["vulnerability_name"] = exception.vulnerability.pluginname
            if exception.host:
                data["hostname"] = exception.host.hostname
                data["host_ip"] = exception.host.host_ip
            response_data.append(ExceptionResponse(**data))
        
        result = PaginatedExceptionResponse(
            exceptions=response_data,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )
        print(f"Returning paginated response: {result}")
        return result
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch exceptions: {str(e)}"
        )
    finally:
        session.close()

@router.get("/exceptions/summary")
def get_exceptions_summary():
    """Get summary statistics for exceptions"""
    session: Session = SessionLocal()
    try:
        current_date = date.today()
        
        # Total active exceptions
        total_active = session.query(VulnerabilityException).filter(
            VulnerabilityException.is_active == True
        ).count()
        
        # Expired exceptions
        expired = session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date < current_date
            )
        ).count()
        
        # Exceptions expiring soon (within 7 days)
        expiring_soon = session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date,
                VulnerabilityException.expiry_date <= current_date + timedelta(days=7)
            )
        ).count()
        
        # Count by type
        by_type = session.query(
            VulnerabilityException.exception_type,
            func.count(VulnerabilityException.id)
        ).filter(
            VulnerabilityException.is_active == True
        ).group_by(VulnerabilityException.exception_type).all()
        
        type_counts = {row[0]: row[1] for row in by_type}
        
        return {
            "total_active": total_active,
            "expired": expired,
            "expiring_soon": expiring_soon,
            "by_type": type_counts
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch exceptions summary: {str(e)}"
        )
    finally:
        session.close()

@router.get("/exceptions/{exception_id}", response_model=ExceptionResponse)
def get_exception(exception_id: str):
    """Get a specific exception by exception_id"""
    session: Session = SessionLocal()
    try:
        exception = session.query(VulnerabilityException).filter(
            VulnerabilityException.exception_id == exception_id
        ).first()
        
        if not exception:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Exception not found"
            )
        
        data = exception.to_dict()
        if exception.vulnerability:
            data["vulnerability_name"] = exception.vulnerability.pluginname
        if exception.host:
            data["hostname"] = exception.host.hostname
            data["host_ip"] = exception.host.host_ip
        
        return ExceptionResponse(**data)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch exception: {str(e)}"
        )
    finally:
        session.close()

@router.put("/exceptions/{exception_id}", response_model=ExceptionResponse)
def update_exception(exception_id: str, update_data: ExceptionUpdateRequest):
    """Update an existing exception"""
    session: Session = SessionLocal()
    try:
        exception = session.query(VulnerabilityException).filter(
            VulnerabilityException.exception_id == exception_id
        ).first()
        
        if not exception:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Exception not found"
            )
        
        # Update fields if provided
        if update_data.reason is not None:
            exception.reason = update_data.reason
        if update_data.expiry_date is not None:
            exception.expiry_date = update_data.expiry_date
        if update_data.is_active is not None:
            exception.is_active = update_data.is_active
        
        session.commit()
        session.refresh(exception)
        
        data = exception.to_dict()
        if exception.vulnerability:
            data["vulnerability_name"] = exception.vulnerability.pluginname
        if exception.host:
            data["hostname"] = exception.host.hostname
            data["host_ip"] = exception.host.host_ip
        
        return ExceptionResponse(**data)
        
    except HTTPException:
        session.rollback()
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update exception: {str(e)}"
        )
    finally:
        session.close()

@router.delete("/exceptions/{exception_id}")
def delete_exception(exception_id: str):
    """Delete an exception"""
    session: Session = SessionLocal()
    try:
        exception = session.query(VulnerabilityException).filter(
            VulnerabilityException.exception_id == exception_id
        ).first()
        
        if not exception:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Exception not found"
            )
        
        session.delete(exception)
        session.commit()
        
        return {"message": "Exception deleted successfully"}
        
    except HTTPException:
        session.rollback()
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete exception: {str(e)}"
        )
    finally:
        session.close()

@router.get("/exceptions/check/{vulnerability_id}/{host_id}")
def check_exception(vulnerability_id: int, host_id: int):
    """Check if a specific vulnerability-host combination has an active exception"""
    session: Session = SessionLocal()
    try:
        current_date = date.today()
        
        # Check for specific vulnerability-host exception
        specific_exception = session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.vulnerability_id == vulnerability_id,
                VulnerabilityException.host_id == host_id,
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date
            )
        ).first()
        
        if specific_exception:
            return {
                "has_exception": True,
                "exception_id": specific_exception.exception_id,
                "exception_type": "vulnerability_host",
                "reason": specific_exception.reason,
                "expiry_date": specific_exception.expiry_date.isoformat()
            }
        
        # Check for vulnerability-only exception
        vuln_exception = session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.vulnerability_id == vulnerability_id,
                VulnerabilityException.host_id.is_(None),
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date
            )
        ).first()
        
        if vuln_exception:
            return {
                "has_exception": True,
                "exception_id": vuln_exception.exception_id,
                "exception_type": "vulnerability",
                "reason": vuln_exception.reason,
                "expiry_date": vuln_exception.expiry_date.isoformat()
            }
        
        # Check for host-only exception
        host_exception = session.query(VulnerabilityException).filter(
            and_(
                VulnerabilityException.host_id == host_id,
                VulnerabilityException.vulnerability_id.is_(None),
                VulnerabilityException.is_active == True,
                VulnerabilityException.expiry_date >= current_date
            )
        ).first()
        
        if host_exception:
            return {
                "has_exception": True,
                "exception_id": host_exception.exception_id,
                "exception_type": "host",
                "reason": host_exception.reason,
                "expiry_date": host_exception.expiry_date.isoformat()
            }
        
        return {"has_exception": False}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check exception: {str(e)}"
        )
    finally:
        session.close()

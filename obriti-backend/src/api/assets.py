from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from pydantic import BaseModel, validator
from typing import Optional, List
from datetime import datetime
from services.db import SessionLocal
from models.vuln import Host
from api.scan import get_current_user, require_permission

router = APIRouter(dependencies=[Depends(require_permission("asset_management"))])

# Pydantic models for request/response
class AssetBase(BaseModel):
    hostname: str
    host_ip: str
    server_owner: Optional[str] = None
    application_dependent: Optional[str] = None
    os_name: Optional[str] = "Unknown"
    status: Optional[str] = "active"

class AssetCreate(AssetBase):
    @validator('host_ip')
    def validate_ip(cls, v):
        if not v or not v.strip():
            raise ValueError('IP address is required')
        return v.strip()
    
    @validator('hostname')
    def validate_hostname(cls, v):
        if not v or not v.strip():
            raise ValueError('Hostname is required')
        return v.strip()

class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    host_ip: Optional[str] = None
    server_owner: Optional[str] = None
    application_dependent: Optional[str] = None
    os_name: Optional[str] = None
    status: Optional[str] = None

class AssetResponse(AssetBase):
    id: int
    last_scan_date: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class AssetListResponse(BaseModel):
    assets: List[AssetResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/assets", response_model=AssetResponse, status_code=201)
def create_asset(asset: AssetCreate, db: Session = Depends(get_db)):
    """Create a new asset/host"""
    try:
        # Check if asset with same IP already exists
        existing_asset = db.query(Host).filter(Host.host_ip == asset.host_ip).first()
        if existing_asset:
            raise HTTPException(status_code=400, detail=f"Asset with IP {asset.host_ip} already exists")
        
        # Create new asset
        db_asset = Host(
            hostname=asset.hostname,
            host_ip=asset.host_ip,
            server_owner=asset.server_owner,
            application_dependent=asset.application_dependent,
            os_name=asset.os_name,
            status=asset.status
        )
        
        db.add(db_asset)
        db.commit()
        db.refresh(db_asset)
        
        return AssetResponse(
            id=db_asset.id,
            hostname=db_asset.hostname,
            host_ip=db_asset.host_ip,
            server_owner=db_asset.server_owner,
            application_dependent=db_asset.application_dependent,
            os_name=db_asset.os_name,
            status=db_asset.status,
            last_scan_date=db_asset.last_scan_date
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create asset: {str(e)}")

@router.get("/assets", response_model=AssetListResponse)
def get_assets(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Number of items per page"),
    search: str = Query("", description="Search in hostname or IP"),
    status: str = Query("all", description="Filter by status"),
    owner: str = Query("all", description="Filter by server owner"),
    os_type: str = Query("all", description="Filter by OS type"),
    db: Session = Depends(get_db)
):
    """Get all assets with pagination and filtering"""
    try:
        query = db.query(Host)
        
        # Search filter
        if search:
            like = f"%{search.lower()}%"
            query = query.filter(
                or_(
                    Host.hostname.ilike(like),
                    Host.host_ip.ilike(like)
                )
            )
        
        # Status filter
        if status != "all":
            query = query.filter(Host.status == status)
        
        # Owner filter
        if owner != "all":
            query = query.filter(Host.server_owner == owner)
        
        # OS type filter
        if os_type != "all":
            query = query.filter(Host.os_name == os_type)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        assets = (
            query
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )
        
        # Convert to response model
        asset_list = []
        for asset in assets:
            asset_list.append(AssetResponse(
                id=asset.id,
                hostname=asset.hostname,
                host_ip=asset.host_ip,
                server_owner=asset.server_owner,
                application_dependent=asset.application_dependent,
                os_name=asset.os_name,
                status=asset.status,
                last_scan_date=asset.last_scan_date
            ))
        
        total_pages = (total + page_size - 1) // page_size
        
        return AssetListResponse(
            assets=asset_list,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve assets: {str(e)}")

@router.get("/assets/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    """Get a specific asset by ID"""
    try:
        asset = db.query(Host).filter(Host.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found")
        
        return AssetResponse(
            id=asset.id,
            hostname=asset.hostname,
            host_ip=asset.host_ip,
            server_owner=asset.server_owner,
            application_dependent=asset.application_dependent,
            os_name=asset.os_name,
            status=asset.status,
            last_scan_date=asset.last_scan_date
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve asset: {str(e)}")

@router.put("/assets/{asset_id}", response_model=AssetResponse)
def update_asset(asset_id: int, asset_update: AssetUpdate, db: Session = Depends(get_db)):
    """Update an existing asset"""
    try:
        # Find the asset
        db_asset = db.query(Host).filter(Host.id == asset_id).first()
        if not db_asset:
            raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found")
        
        # Check if IP is being updated and if it conflicts with existing asset
        if asset_update.host_ip and asset_update.host_ip != db_asset.host_ip:
            existing_asset = db.query(Host).filter(
                Host.host_ip == asset_update.host_ip,
                Host.id != asset_id
            ).first()
            if existing_asset:
                raise HTTPException(status_code=400, detail=f"Asset with IP {asset_update.host_ip} already exists")
        
        # Update fields
        update_data = asset_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_asset, field, value)
        
        db.commit()
        db.refresh(db_asset)
        
        return AssetResponse(
            id=db_asset.id,
            hostname=db_asset.hostname,
            host_ip=db_asset.host_ip,
            server_owner=db_asset.server_owner,
            application_dependent=db_asset.application_dependent,
            os_name=db_asset.os_name,
            status=db_asset.status,
            last_scan_date=db_asset.last_scan_date
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update asset: {str(e)}")

@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    """Delete an asset"""
    try:
        asset = db.query(Host).filter(Host.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found")
        
        # Check if asset has vulnerabilities
        if asset.vulnerabilities:
            raise HTTPException(
                status_code=400, 
                detail="Cannot delete asset that has associated vulnerabilities. Remove vulnerabilities first."
            )
        
        db.delete(asset)
        db.commit()
        
        return {"message": f"Asset {asset.hostname} ({asset.host_ip}) deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete asset: {str(e)}")

@router.delete("/assets/bulk")
def delete_multiple_assets(asset_ids: List[int], db: Session = Depends(get_db)):
    """Delete multiple assets"""
    try:
        assets = db.query(Host).filter(Host.id.in_(asset_ids)).all()
        
        if not assets:
            raise HTTPException(status_code=404, detail="No assets found with provided IDs")
        
        deleted_count = 0
        failed_deletions = []
        
        for asset in assets:
            try:
                # Check if asset has vulnerabilities
                if asset.vulnerabilities:
                    failed_deletions.append({
                        "id": asset.id,
                        "hostname": asset.hostname,
                        "host_ip": asset.host_ip,
                        "reason": "Asset has associated vulnerabilities"
                    })
                    continue
                
                db.delete(asset)
                deleted_count += 1
            except Exception as e:
                failed_deletions.append({
                    "id": asset.id,
                    "hostname": asset.hostname,
                    "host_ip": asset.host_ip,
                    "reason": str(e)
                })
        
        db.commit()
        
        return {
            "message": f"Deleted {deleted_count} assets successfully",
            "deleted_count": deleted_count,
            "failed_deletions": failed_deletions
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete assets: {str(e)}")

@router.get("/assets/stats/summary")
def get_assets_summary(db: Session = Depends(get_db)):
    """Get summary statistics for assets"""
    try:
        # Check if Host table exists
        try:
            total_assets = db.query(Host).count()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Database error - Host table may not exist: {str(e)}")
        
        active_assets = db.query(Host).filter(Host.status == "active").count()
        inactive_assets = db.query(Host).filter(Host.status == "inactive").count()
        
        # OS distribution
        try:
            os_stats = db.query(Host.os_name, db.func.count(Host.id)).group_by(Host.os_name).all()
            os_distribution = {os_name or "Unknown": count for os_name, count in os_stats}
        except Exception as e:
            os_distribution = {"Unknown": total_assets}
        
        # Owner distribution
        try:
            owner_stats = db.query(Host.server_owner, db.func.count(Host.id)).group_by(Host.server_owner).all()
            owner_distribution = {owner or "Unknown": count for owner, count in owner_stats}
        except Exception as e:
            owner_distribution = {"Unknown": total_assets}
        
        return {
            "total_assets": total_assets,
            "active_assets": active_assets,
            "inactive_assets": inactive_assets,
            "os_distribution": os_distribution,
            "owner_distribution": owner_distribution
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get assets summary: {str(e)}")

@router.get("/assets/owners")
def get_asset_owners(db: Session = Depends(get_db)):
    """Get list of all asset owners"""
    try:
        owners = db.query(Host.server_owner).distinct().filter(Host.server_owner.isnot(None)).all()
        return {"owners": [owner[0] for owner in owners]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get asset owners: {str(e)}")

@router.get("/assets/os-types")
def get_os_types(db: Session = Depends(get_db)):
    """Get list of all OS types"""
    try:
        os_types = db.query(Host.os_name).distinct().filter(Host.os_name.isnot(None)).all()
        return {"os_types": [os_type[0] for os_type in os_types]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get OS types: {str(e)}") 
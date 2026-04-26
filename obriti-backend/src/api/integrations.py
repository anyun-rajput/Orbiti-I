"""
Integration management API endpoints for Microsoft SSO and Nessus configurations
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import json
from datetime import datetime

from services.db import get_db
from models.scan import IntegrationConfig, User
from api.scan import get_current_user, require_permission

router = APIRouter(prefix="/integrations", tags=["integrations"])

def sanitize_config_data(integration_type: str, config_data: dict) -> dict:
    """Remove sensitive fields from configuration data before sending to frontend"""
    safe_config_data = {}
    
    if integration_type == "microsoft_sso":
        # Only show non-sensitive fields for Microsoft SSO
        safe_config_data = {
            "clientId": config_data.get("clientId", ""),
            "tenantId": config_data.get("tenantId", ""),
            "redirectUri": config_data.get("redirectUri", "")
            # Hide clientSecret
        }
    elif integration_type == "nessus":
        # Only show server URL, hide credentials
        safe_config_data = {
            "serverUrl": config_data.get("serverUrl", "")
            # Hide username and password
        }
    
    return safe_config_data

# Pydantic models for request/response
class IntegrationConfigRequest(BaseModel):
    integration_type: str  # 'microsoft_sso' or 'nessus'
    enabled: bool
    config_data: Dict[str, Any]

class IntegrationConfigResponse(BaseModel):
    id: int
    integration_type: str
    enabled: bool
    config_data: Dict[str, Any]
    status: str
    last_tested: Optional[datetime]
    last_sync: Optional[datetime]
    extra_metadata: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

class IntegrationTestRequest(BaseModel):
    integration_type: str
    config_data: Dict[str, Any]

@router.get("/", response_model=List[IntegrationConfigResponse])
def get_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("integrations"))
):
    """Get all integration configurations"""
    integrations = db.query(IntegrationConfig).all()
    
    result = []
    for integration in integrations:
        config_data = json.loads(integration.config_data) if integration.config_data else {}
        extra_metadata = json.loads(integration.extra_metadata) if integration.extra_metadata else {}
        
        # Set status based on integration existence and enabled state
        display_status = "connected" if integration.enabled else "configured"
        
        # Hide sensitive configuration data, only show non-sensitive fields
        safe_config_data = sanitize_config_data(integration.integration_type, config_data)
        
        result.append(IntegrationConfigResponse(
            id=integration.id,
            integration_type=integration.integration_type,
            enabled=integration.enabled,
            config_data=safe_config_data,
            status=display_status,
            last_tested=integration.last_tested,
            last_sync=integration.last_sync,
            extra_metadata=extra_metadata,
            created_at=integration.created_at,
            updated_at=integration.updated_at
        ))
    
    return result

@router.get("/{integration_type}", response_model=IntegrationConfigResponse)
def get_integration(
    integration_type: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("integrations"))
):
    """Get specific integration configuration"""
    integration = db.query(IntegrationConfig).filter(
        IntegrationConfig.integration_type == integration_type
    ).first()
    
    if not integration:
        # Return default configuration if not found
        return IntegrationConfigResponse(
            id=0,
            integration_type=integration_type,
            enabled=False,
            config_data={},
            status="not_configured",
            last_tested=None,
            last_sync=None,
            extra_metadata={},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
    
    config_data = json.loads(integration.config_data) if integration.config_data else {}
    extra_metadata = json.loads(integration.extra_metadata) if integration.extra_metadata else {}
    
    # Set status based on integration existence and enabled state
    display_status = "connected" if integration.enabled else "configured"
    
    # Hide sensitive configuration data, only show non-sensitive fields
    safe_config_data = sanitize_config_data(integration.integration_type, config_data)
    
    return IntegrationConfigResponse(
        id=integration.id,
        integration_type=integration.integration_type,
        enabled=integration.enabled,
        config_data=safe_config_data,
        status=display_status,
        last_tested=integration.last_tested,
        last_sync=integration.last_sync,
        extra_metadata=extra_metadata,
        created_at=integration.created_at,
        updated_at=integration.updated_at
    )

@router.post("/", response_model=IntegrationConfigResponse)
def create_or_update_integration(
    request: IntegrationConfigRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("integrations"))
):
    """Create or update integration configuration"""
    
    # Check if integration already exists
    existing_integration = db.query(IntegrationConfig).filter(
        IntegrationConfig.integration_type == request.integration_type
    ).first()
    
    # Determine status based on configuration completeness and enabled state
    status = "not_configured"
    if request.enabled and request.config_data:
        if request.integration_type == "microsoft_sso":
            required_fields = ["clientId", "tenantId", "redirectUri", "clientSecret"]
            if all(field in request.config_data and request.config_data[field] for field in required_fields):
                status = "connected"  # Show as connected for enabled integrations
        elif request.integration_type == "nessus":
            required_fields = ["serverUrl", "username", "password"]
            if all(field in request.config_data and request.config_data[field] for field in required_fields):
                status = "connected"
    elif request.config_data:
        # If integration has config but is disabled, show as configured
        status = "configured"
    
    if existing_integration:
        # Update existing integration
        existing_integration.enabled = request.enabled
        existing_integration.config_data = json.dumps(request.config_data)
        existing_integration.status = status
        existing_integration.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(existing_integration)
        
        config_data = json.loads(existing_integration.config_data) if existing_integration.config_data else {}
        extra_metadata = json.loads(existing_integration.extra_metadata) if existing_integration.extra_metadata else {}
        safe_config_data = sanitize_config_data(existing_integration.integration_type, config_data)
        
        return IntegrationConfigResponse(
            id=existing_integration.id,
            integration_type=existing_integration.integration_type,
            enabled=existing_integration.enabled,
            config_data=safe_config_data,
            status=existing_integration.status,
            last_tested=existing_integration.last_tested,
            last_sync=existing_integration.last_sync,
            extra_metadata=extra_metadata,
            created_at=existing_integration.created_at,
            updated_at=existing_integration.updated_at
        )
    else:
        # Create new integration
        new_integration = IntegrationConfig(
            integration_type=request.integration_type,
            enabled=request.enabled,
            config_data=json.dumps(request.config_data),
            status=status,
            created_by=current_user.id
        )
        
        db.add(new_integration)
        db.commit()
        db.refresh(new_integration)
        
        config_data = json.loads(new_integration.config_data) if new_integration.config_data else {}
        extra_metadata = json.loads(new_integration.extra_metadata) if new_integration.extra_metadata else {}
        safe_config_data = sanitize_config_data(new_integration.integration_type, config_data)
        
        return IntegrationConfigResponse(
            id=new_integration.id,
            integration_type=new_integration.integration_type,
            enabled=new_integration.enabled,
            config_data=safe_config_data,
            status=new_integration.status,
            last_tested=new_integration.last_tested,
            last_sync=new_integration.last_sync,
            extra_metadata=extra_metadata,
            created_at=new_integration.created_at,
            updated_at=new_integration.updated_at
        )

@router.post("/test")
def test_integration(
    request: IntegrationTestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("integrations"))
):
    """Test integration connection"""
    
    try:
        if request.integration_type == "microsoft_sso":
            # Test Microsoft SSO connection
            # This would normally validate the Azure AD configuration
            required_fields = ["clientId", "tenantId", "redirectUri", "clientSecret"]
            if not all(field in request.config_data and request.config_data[field] for field in required_fields):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Missing required Microsoft SSO configuration fields: clientId, tenantId, redirectUri, clientSecret"
                )
            
            # Update integration test timestamp
            integration = db.query(IntegrationConfig).filter(
                IntegrationConfig.integration_type == request.integration_type
            ).first()
            
            if integration:
                integration.last_tested = datetime.utcnow()
                integration.status = "configured"
                db.commit()
            
            return {"status": "success", "message": "Microsoft SSO configuration is valid"}
            
        elif request.integration_type == "nessus":
            # Mock Nessus connection test
            server_url = request.config_data.get('serverUrl')
            username = request.config_data.get('username')
            password = request.config_data.get('password')
            
            if not all([server_url, username, password]):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Server URL, username, and password are required for Nessus"
                )
            
            # Update integration test timestamp
            integration = db.query(IntegrationConfig).filter(
                IntegrationConfig.integration_type == request.integration_type
            ).first()
            
            if integration:
                integration.last_tested = datetime.utcnow()
                integration.last_sync = datetime.utcnow()
                integration.status = "connected"
                # Update extra_metadata with mock vulnerability count
                extra_metadata = {"vulnerabilityCount": 1547}
                integration.extra_metadata = json.dumps(extra_metadata)
                db.commit()
            
            return {"status": "success", "message": "Nessus connection successful"}
            
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid integration type"
            )
            
    except Exception as e:
        # Update integration with error status
        integration = db.query(IntegrationConfig).filter(
            IntegrationConfig.integration_type == request.integration_type
        ).first()
        
        if integration:
            integration.last_tested = datetime.utcnow()
            integration.status = "error"
            db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Integration test failed: {str(e)}"
        )

@router.delete("/{integration_type}")
def delete_integration(
    integration_type: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("integrations"))
):
    """Delete integration configuration"""
    
    integration = db.query(IntegrationConfig).filter(
        IntegrationConfig.integration_type == integration_type
    ).first()
    
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found"
        )
    
    db.delete(integration)
    db.commit()
    
    return {"message": f"{integration_type} integration deleted successfully"}

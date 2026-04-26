from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from models.scan import User, Role
from services.db import get_db
import bcrypt
import jwt
import os
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, validator
from typing import Optional
import asyncio
from services.nessus_service import fetch_running_scans, fetch_scan_details
from services.microsoft_sso_service import microsoft_sso_service
from config.microsoft_sso import microsoft_sso_config
from utils.rate_limiter import login_rate_limit, api_rate_limit
from utils.validation import SearchRequest, HostCreateRequest, CommentCreateRequest
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-use-a-strong-random-string")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

auth_router = APIRouter()

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# Moved to utils.auth_utils to avoid circular imports
from utils.auth_utils import create_access_token

class UserCreate(BaseModel):
    username: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: str

class Token(BaseModel):
    access_token: str
    token_type: str

class MicrosoftSSOResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

class MicrosoftAuthRequest(BaseModel):
    code: str
    state: Optional[str] = None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if user is None:
        raise credentials_exception
    return user

def get_current_admin_user(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Dependency to ensure current user is admin"""
    if not current_user.role or current_user.role.name != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

def require_permission(permission: str):
    """Dependency factory to require specific permission"""
    def permission_checker(current_user: User = Depends(get_current_user)):
        if not current_user.role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User role not found"
            )
        
        # Define permissions for each role
        if current_user.role.name == "admin":
            # Admin has all permissions
            return current_user
        elif current_user.role.name == "org_team":
            # org_team only has limited permissions
            allowed_permissions = ["dashboard", "vulnerabilities", "vuln_by_owner", "vuln_by_hosts", "closed_vulnerabilities", "exceptions"]
            if permission not in allowed_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{permission}' required. Access denied for org_team role."
                )
            return current_user
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid user role"
            )
    
    return permission_checker

@auth_router.post("/register", response_model=Token)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter((User.username == user.username) | (User.email == user.email)).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        hashed_password=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        auth_provider='local'  # Set as local authentication
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    access_token = create_access_token(data={"sub": new_user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@auth_router.post("/login", response_model=Token)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db)
):
    # Apply rate limiting
    login_rate_limit(request)
    
    # Validate input
    if not form_data.username or not form_data.password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    
    if len(form_data.username) > 255:
        raise HTTPException(status_code=400, detail="Username too long")
    
    if len(form_data.password) > 255:
        raise HTTPException(status_code=400, detail="Password too long")
    
    user = db.query(User).filter(User.username == form_data.username, User.is_active == True).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@auth_router.post("/long_lived_token", response_model=Token)
def get_long_lived_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    days: int = 30
):
    """
    Obtain a long-lived API key (JWT) by providing username and password.
    The token will be valid for the specified number of days (default: 30).
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    # Cap the maximum allowed duration for security (e.g., 180 days)
    max_days = 365
    if days > max_days:
        days = max_days
    expires_delta = timedelta(days=days)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=expires_delta)
    return {"access_token": access_token, "token_type": "bearer"}

# Example of protecting an endpoint:
@auth_router.get("/protected")
def protected_route(current_user: User = Depends(get_current_user)):
    return {"msg": f"Hello, {current_user.username}!"}

@auth_router.get("/validate")
def validate_token(current_user: User = Depends(get_current_user)):
    """Validate the current user's token"""
    return {"valid": True, "user": current_user.username}

# Microsoft SSO endpoints
@auth_router.get("/microsoft/config")
def get_microsoft_sso_config(db: Session = Depends(get_db)):
    """Get Microsoft SSO configuration status - prioritize database configuration"""
    # Check dynamic configuration from database first
    dynamic_config = microsoft_sso_service._get_dynamic_config(db)
    
    if dynamic_config:
        # Database configuration exists and is enabled
        required_fields = ["clientId", "tenantId", "redirectUri", "clientSecret"]
        enabled = all(field in dynamic_config and dynamic_config[field] for field in required_fields)
        
        return {
            "enabled": enabled,
            "client_id": dynamic_config.get('clientId'),
            "redirect_uri": dynamic_config.get('redirectUri', microsoft_sso_config.REDIRECT_URI)
        }
    
    # Fallback to static configuration only if no database config
    static_configured = microsoft_sso_config.is_configured()
    
    if static_configured:
        return {
            "enabled": True,
            "client_id": microsoft_sso_config.CLIENT_ID,
            "redirect_uri": microsoft_sso_config.REDIRECT_URI
        }
    else:
        return {
            "enabled": False,
            "client_id": None,
            "redirect_uri": microsoft_sso_config.REDIRECT_URI
        }

@auth_router.get("/microsoft/login")
def microsoft_login_url(state: Optional[str] = None, db: Session = Depends(get_db)):
    """Get Microsoft SSO login URL using dynamic configuration"""
    auth_url = microsoft_sso_service.get_auth_url(db, state)
    if not auth_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Microsoft SSO is not configured or enabled"
        )
    
    return {"auth_url": auth_url}

@auth_router.post("/microsoft/callback", response_model=MicrosoftSSOResponse)
def microsoft_callback(auth_request: MicrosoftAuthRequest, db: Session = Depends(get_db)):
    """Handle Microsoft SSO callback (POST endpoint for frontend)"""
    if not microsoft_sso_config.is_configured():
        raise HTTPException(
            status_code=503,
            detail="Microsoft SSO is not configured"
        )
    
    try:
        # Exchange code for token first to get detailed error info
        token_result = microsoft_sso_service.exchange_code_for_token(auth_request.code, db)
        
        if not token_result:
            raise HTTPException(
                status_code=400,
                detail="Microsoft authentication failed - unable to exchange authorization code"
            )
        
        # Check if token_result contains an error
        if "error" in token_result:
            error_code = token_result.get('error', 'unknown_error')
            error_desc = token_result.get('error_description', 'Microsoft authentication failed')
            
            # Create user-friendly error messages
            if error_code == 'invalid_client':
                if 'client secret' in error_desc.lower():
                    friendly_error = "Invalid client secret. Please check your Microsoft SSO configuration."
                else:
                    friendly_error = "Invalid client configuration. Please verify your Azure AD app settings."
            elif error_code == 'invalid_grant':
                friendly_error = "Authorization code expired or invalid. Please try logging in again."
            elif error_code == 'unauthorized_client':
                friendly_error = "Application not authorized. Please check your Azure AD app permissions."
            elif error_code == 'invalid_request':
                friendly_error = "Invalid authentication request. Please check your configuration."
            else:
                friendly_error = f"Microsoft authentication failed: {error_desc}"
            
            raise HTTPException(
                status_code=400,
                detail=friendly_error
            )
        
        # Get user info from Microsoft Graph
        user_info = microsoft_sso_service.get_user_info(token_result['access_token'])
        if not user_info:
            raise HTTPException(
                status_code=400,
                detail="Failed to retrieve user information from Microsoft Graph"
            )
        
        # Create or update user in database
        user = microsoft_sso_service.create_or_update_user(user_info, db)
        if not user:
            raise HTTPException(
                status_code=400,
                detail="Failed to create or update user account"
            )
        
        # Generate JWT token for our application
        from services.auth import create_access_token
        from datetime import timedelta
        
        access_token = create_access_token(
            data={"sub": user.username},
            expires_delta=timedelta(minutes=60)
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "role": user.role.name if user.role else "unknown",
                "auth_provider": user.auth_provider
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Microsoft callback error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Authentication server error: {str(e)}"
        )

# To protect all endpoints in this router, add Depends(get_current_user) to each route or use a dependency in the router itself.

router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/scans/running")
async def get_running_scans(current_user: User = Depends(require_permission("scan_management"))):
    loop = asyncio.get_event_loop()
    running_scans = await loop.run_in_executor(None, fetch_running_scans)
    if running_scans is None:
        raise HTTPException(status_code=502, detail="Could not fetch running scans from Nessus.")
    return {"running_scans": running_scans}

@router.get("/scans/{scan_id}")
async def get_scan_details(
    scan_id: str,
    isinventoryscan: bool = Query(False, description="Is inventory scan"),
    current_user: User = Depends(require_permission("scan_management"))
):
    """
    Get detailed scan results for a specific scan ID.
    Handles large datasets with optimized processing.
    """
    try:
        # Validate scan_id format
        if not scan_id or not scan_id.isdigit():
            raise HTTPException(status_code=400, detail="Invalid scan ID format")

        print(f"API request: Fetching scan details for scan ID {scan_id} (inventory: {isinventoryscan})")

        # Add timeout handling for large scans
        import asyncio
        try:
            # Set a reasonable timeout for large scans (30 minutes)
            scan_details = await asyncio.wait_for(
                fetch_scan_details(scan_id, isinventoryscan),
                timeout=1800  # 30 minutes
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=504,
                detail="Scan processing timed out. The scan may be too large or there may be server issues. Please try again later."
            )

        if scan_details is None or (isinstance(scan_details, list) and len(scan_details) == 0):
            raise HTTPException(
                status_code=404,
                detail=f"No scan data found for scan ID {scan_id}. The scan may not exist or may still be processing."
            )

        return {
            "scan_details": scan_details,
            "isinventoryscan": isinventoryscan,
            "total_findings": len(scan_details) if isinstance(scan_details, list) else 0
        }

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        print(f"Unexpected error in get_scan_details: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error while processing scan {scan_id}: {str(e)}"
        )

class ImmediateScanRequest(BaseModel):
    host_ips: list[str]
    scan_type: str = "ready_hosts_rescan"

@router.post("/scans/immediate")
async def start_immediate_scan(request: ImmediateScanRequest, current_admin: User = Depends(get_current_admin_user)):
    """Start an immediate scan for ready hosts"""
    try:
        from services.vuln_scan import start_immediate_scan_for_hosts
        
        # Check if any scan is already running
        loop = asyncio.get_event_loop()
        running_scans = await loop.run_in_executor(None, fetch_running_scans)
        
        if running_scans and len(running_scans) > 0:
            return {
                "message": "A scan is already running. Ready hosts will be scanned after current scan completes.",
                "status": "queued",
                "running_scan_id": running_scans[0].get("id"),
                "ready_hosts_count": len(request.host_ips)
            }
        
        # Start immediate scan
        result = await start_immediate_scan_for_hosts(request.host_ips, request.scan_type)
        
        return {
            "message": f"Immediate scan started for {len(request.host_ips)} ready hosts",
            "status": "started",
            "scan_id": result.get("scan_id"),
            "host_count": len(request.host_ips)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start immediate scan: {str(e)}")

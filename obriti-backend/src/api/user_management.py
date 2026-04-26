from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from models.scan import User, Role
from services.db import get_db
from api.scan import get_current_admin_user, get_password_hash, get_current_user
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

router = APIRouter()

# Pydantic models for API responses
class UserResponse(BaseModel):
    id: int
    username: str
    first_name: Optional[str]
    last_name: Optional[str]
    email: str
    role_name: str
    is_active: bool
    auth_provider: Optional[str]
    external_id: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class RoleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    username: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: str
    role_name: str = "org_team"

class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    role_name: Optional[str] = None
    is_active: Optional[bool] = None

class CurrentUserResponse(BaseModel):
    id: int
    username: str
    first_name: Optional[str]
    last_name: Optional[str]
    email: str
    role_name: str
    permissions: List[str]

    class Config:
        from_attributes = True

# Get current user info with permissions
@router.get("/me", response_model=CurrentUserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information with role and permissions"""
    permissions = []
    if current_user.role:
        if current_user.role.name == "admin":
            permissions = [
                "dashboard", "scan_management", "asset_management", 
                "vulnerabilities", "vuln_by_owner", "vuln_by_hosts", "closed_vulnerabilities", "exceptions",
                "integrations", "settings", "user_management"
            ]
        elif current_user.role.name == "org_team":
            permissions = ["dashboard", "vulnerabilities", "vuln_by_owner", "vuln_by_hosts", "closed_vulnerabilities", "exceptions"]
    
    return CurrentUserResponse(
        id=current_user.id,
        username=current_user.username,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        email=current_user.email,
        role_name=current_user.role.name if current_user.role else "unknown",
        permissions=permissions
    )

# Admin-only endpoints for user management
@router.get("/users", response_model=List[UserResponse])
def get_all_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: str = Query("", description="Search by username, email, or name"),
    role_filter: str = Query("all", description="Filter by role: all, admin, org_team"),
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get all users (admin only)"""
    query = db.query(User).join(Role)
    
    # Apply search filter
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            (User.username.ilike(search_filter)) |
            (User.email.ilike(search_filter)) |
            (User.first_name.ilike(search_filter)) |
            (User.last_name.ilike(search_filter))
        )
    
    # Apply role filter
    if role_filter != "all":
        query = query.filter(Role.name == role_filter)
    
    users = query.offset(skip).limit(limit).all()
    
    return [
        UserResponse(
            id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role_name=user.role.name if user.role else "unknown",
            is_active=user.is_active,
            auth_provider=user.auth_provider,
            external_id=user.external_id,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
        for user in users
    ]

@router.post("/users", response_model=UserResponse)
def create_user(
    user_data: UserCreate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Create a new user (admin only)"""
    # Check if username or email already exists
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username or email already exists"
        )
    
    # Get role
    role = db.query(Role).filter(Role.name == user_data.role_name).first()
    if not role:
        raise HTTPException(
            status_code=400,
            detail=f"Role '{user_data.role_name}' not found"
        )
    
    # Create user
    hashed_password = get_password_hash(user_data.password)
    new_user = User(
        username=user_data.username,
        hashed_password=hashed_password,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        email=user_data.email,
        role_id=role.id,
        is_active=True
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return UserResponse(
        id=new_user.id,
        username=new_user.username,
        first_name=new_user.first_name,
        last_name=new_user.last_name,
        email=new_user.email,
        role_name=new_user.role.name,
        is_active=new_user.is_active,
        auth_provider=new_user.auth_provider,
        external_id=new_user.external_id,
        created_at=new_user.created_at,
        updated_at=new_user.updated_at
    )

@router.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Update a user (admin only)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update fields if provided
    if user_data.first_name is not None:
        user.first_name = user_data.first_name
    if user_data.last_name is not None:
        user.last_name = user_data.last_name
    if user_data.email is not None:
        # Check if email is already taken by another user
        existing_user = db.query(User).filter(
            User.email == user_data.email,
            User.id != user_id
        ).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already exists")
        user.email = user_data.email
    
    if user_data.role_name is not None:
        role = db.query(Role).filter(Role.name == user_data.role_name).first()
        if not role:
            raise HTTPException(status_code=400, detail=f"Role '{user_data.role_name}' not found")
        user.role_id = role.id
    
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
    
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    
    return UserResponse(
        id=user.id,
        username=user.username,
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        role_name=user.role.name,
        is_active=user.is_active,
        auth_provider=user.auth_provider,
        external_id=user.external_id,
        created_at=user.created_at,
        updated_at=user.updated_at
    )

@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Delete a user (admin only)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent admin from deleting themselves
    if user.id == current_admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    db.delete(user)
    db.commit()
    
    return {"message": "User deleted successfully"}

@router.get("/roles", response_model=List[RoleResponse])
def get_all_roles(
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get all roles (admin only)"""
    roles = db.query(Role).all()
    return roles

@router.post("/users/{user_id}/reset-password")
def reset_user_password(
    user_id: int,
    new_password: str,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Reset user password (admin only)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent password reset for SSO users
    if user.auth_provider and user.auth_provider != 'local':
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot reset password for {user.auth_provider} SSO user. Password is managed by the SSO provider."
        )
    
    user.hashed_password = get_password_hash(new_password)
    user.updated_at = datetime.utcnow()
    db.commit()
    
    return {"message": "Password reset successfully"}

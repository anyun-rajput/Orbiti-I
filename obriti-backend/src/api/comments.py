from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime
from functools import lru_cache
import hashlib

from services.db import get_db
from models.comments import Comment, CommentType
from models.vuln import Host, Vulnerability
from api.scan import get_current_user

router = APIRouter()

# Pydantic models
class CommentCreate(BaseModel):
    comment_type: CommentType
    content: str
    vulnerability_id: Optional[int] = None
    host_id: Optional[int] = None

class CommentUpdate(BaseModel):
    content: str

class CommentResponse(BaseModel):
    id: int
    comment_type: CommentType
    content: str
    created_at: datetime
    updated_at: datetime
    created_by: str
    vulnerability_id: Optional[int] = None
    host_id: Optional[int] = None

    class Config:
        from_attributes = True

class BatchCommentResponse(BaseModel):
    host_vulnerability_comments: List[CommentResponse] = []
    host_comments: List[CommentResponse] = []
    vulnerability_comments: List[CommentResponse] = []
    total_count: int = 0
    
class CommentContextRequest(BaseModel):
    vulnerability_id: Optional[int] = None
    host_id: Optional[int] = None
    owner_name: Optional[str] = None

# Create a new comment
@router.post("/comments", response_model=CommentResponse)
async def create_comment(
    comment: CommentCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    # Validate comment type and required fields
    if comment.comment_type == CommentType.VULNERABILITY and not comment.vulnerability_id:
        raise HTTPException(status_code=400, detail="vulnerability_id is required for vulnerability comments")
    
    if comment.comment_type == CommentType.HOST and not comment.host_id:
        raise HTTPException(status_code=400, detail="host_id is required for host comments")
    
    if comment.comment_type == CommentType.HOST_VULNERABILITY and (not comment.host_id or not comment.vulnerability_id):
        raise HTTPException(status_code=400, detail="Both host_id and vulnerability_id are required for host-vulnerability comments")
    
    # Verify that referenced entities exist
    if comment.vulnerability_id:
        vuln = db.query(Vulnerability).filter(Vulnerability.pluginid == comment.vulnerability_id).first()
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    if comment.host_id:
        host = db.query(Host).filter(Host.id == comment.host_id).first()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
    
    # Create the comment
    db_comment = Comment(
        comment_type=comment.comment_type.value,
        content=comment.content,
        vulnerability_id=comment.vulnerability_id,
        host_id=comment.host_id,
        created_by=current_user.username
    )
    
    db.add(db_comment)
    db.commit()
    db.refresh(db_comment)
    
    return db_comment

# Get comments for a specific vulnerability
@router.get("/vulnerabilities/{vulnerability_id}/comments", response_model=List[CommentResponse])
async def get_vulnerability_comments(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    comments = db.query(Comment).filter(
        and_(
            Comment.vulnerability_id == vulnerability_id,
            or_(
                Comment.comment_type == CommentType.VULNERABILITY.value,
                Comment.comment_type == CommentType.HOST_VULNERABILITY.value
            )
        )
    ).order_by(Comment.created_at.desc()).all()
    
    return comments

# Get comments for a specific host
@router.get("/hosts/{host_id}/comments", response_model=List[CommentResponse])
async def get_host_comments(
    host_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    comments = db.query(Comment).filter(
        and_(
            Comment.host_id == host_id,
            or_(
                Comment.comment_type == CommentType.HOST.value,
                Comment.comment_type == CommentType.HOST_VULNERABILITY.value
            )
        )
    ).order_by(Comment.created_at.desc()).all()
    
    return comments

# Optimized batch endpoint for getting comments with intelligent fallback
@router.post("/comments/batch", response_model=BatchCommentResponse)
async def get_comments_batch(
    request: CommentContextRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Optimized endpoint that returns all relevant comments in a single request
    with intelligent prioritization and fallback logic.
    """
    result = BatchCommentResponse()
    
    if request.host_id and request.vulnerability_id:
        # Get host-vulnerability specific comments
        hv_comments = db.query(Comment).filter(
            and_(
                Comment.comment_type == CommentType.HOST_VULNERABILITY.value,
                Comment.host_id == request.host_id,
                Comment.vulnerability_id == request.vulnerability_id
            )
        ).order_by(Comment.created_at.desc()).all()
        result.host_vulnerability_comments = hv_comments
        
        # Get host comments
        host_comments = db.query(Comment).filter(
            and_(
                Comment.comment_type == CommentType.HOST.value,
                Comment.host_id == request.host_id
            )
        ).order_by(Comment.created_at.desc()).all()
        result.host_comments = host_comments
        
        # Get vulnerability comments
        vuln_comments = db.query(Comment).filter(
            and_(
                Comment.comment_type == CommentType.VULNERABILITY.value,
                Comment.vulnerability_id == request.vulnerability_id
            )
        ).order_by(Comment.created_at.desc()).all()
        result.vulnerability_comments = vuln_comments
        
    elif request.host_id:
        # Host-only context
        host_comments = db.query(Comment).filter(
            and_(
                Comment.comment_type == CommentType.HOST.value,
                Comment.host_id == request.host_id
            )
        ).order_by(Comment.created_at.desc()).all()
        result.host_comments = host_comments
        
    elif request.vulnerability_id:
        # Vulnerability-only context
        vuln_comments = db.query(Comment).filter(
            and_(
                Comment.comment_type == CommentType.VULNERABILITY.value,
                Comment.vulnerability_id == request.vulnerability_id
            )
        ).order_by(Comment.created_at.desc()).all()
        result.vulnerability_comments = vuln_comments
        
    elif request.owner_name:
        # Owner context - get comments for hosts owned by this owner
        host_ids = db.query(Host.id).filter(Host.server_owner == request.owner_name).all()
        host_ids = [host_id[0] for host_id in host_ids]
        
        if host_ids:
            owner_comments = db.query(Comment).filter(
                or_(
                    Comment.host_id.in_(host_ids),
                    and_(
                        Comment.comment_type == CommentType.VULNERABILITY.value,
                        Comment.vulnerability_id.in_(
                            db.query(Vulnerability.pluginid).join(Host, Host.id.in_(host_ids))
                        )
                    )
                )
            ).order_by(Comment.created_at.desc()).all()
            
            # Categorize owner comments
            for comment in owner_comments:
                if comment.comment_type == CommentType.HOST.value:
                    result.host_comments.append(comment)
                elif comment.comment_type == CommentType.VULNERABILITY.value:
                    result.vulnerability_comments.append(comment)
                elif comment.comment_type == CommentType.HOST_VULNERABILITY.value:
                    result.host_vulnerability_comments.append(comment)
    
    # Calculate total count
    result.total_count = (
        len(result.host_vulnerability_comments) + 
        len(result.host_comments) + 
        len(result.vulnerability_comments)
    )
    
    return result

# Lightning-fast endpoint for latest comment only
@router.post("/comments/latest", response_model=CommentResponse | None)
async def get_latest_comment(
    request: CommentContextRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Ultra-fast endpoint that returns only the most recent comment for a given context.
    Uses intelligent prioritization: host-vulnerability > host > vulnerability
    """
    latest_comment = None
    
    if request.host_id and request.vulnerability_id:
        # Priority 1: Host-vulnerability specific comments
        latest_comment = db.query(Comment).filter(
            and_(
                Comment.comment_type == CommentType.HOST_VULNERABILITY.value,
                Comment.host_id == request.host_id,
                Comment.vulnerability_id == request.vulnerability_id
            )
        ).order_by(Comment.created_at.desc()).first()
        
        # Priority 2: Host comments (if no host-vuln comments)
        if not latest_comment:
            latest_comment = db.query(Comment).filter(
                and_(
                    Comment.comment_type == CommentType.HOST.value,
                    Comment.host_id == request.host_id
                )
            ).order_by(Comment.created_at.desc()).first()
        
        # Priority 3: Vulnerability comments (fallback)
        if not latest_comment:
            latest_comment = db.query(Comment).filter(
                and_(
                    Comment.comment_type == CommentType.VULNERABILITY.value,
                    Comment.vulnerability_id == request.vulnerability_id
                )
            ).order_by(Comment.created_at.desc()).first()
            
    elif request.host_id:
        # Host-only context
        latest_comment = db.query(Comment).filter(
            and_(
                Comment.comment_type == CommentType.HOST.value,
                Comment.host_id == request.host_id
            )
        ).order_by(Comment.created_at.desc()).first()
        
    elif request.vulnerability_id:
        # Vulnerability-only context
        latest_comment = db.query(Comment).filter(
            and_(
                Comment.comment_type == CommentType.VULNERABILITY.value,
                Comment.vulnerability_id == request.vulnerability_id
            )
        ).order_by(Comment.created_at.desc()).first()
        
    elif request.owner_name:
        # Owner context - get latest comment from hosts owned by this owner
        host_ids = db.query(Host.id).filter(Host.server_owner == request.owner_name).all()
        host_ids = [host_id[0] for host_id in host_ids]
        
        if host_ids:
            latest_comment = db.query(Comment).filter(
                or_(
                    Comment.host_id.in_(host_ids),
                    and_(
                        Comment.comment_type == CommentType.VULNERABILITY.value,
                        Comment.vulnerability_id.in_(
                            db.query(Vulnerability.pluginid).join(Host, Host.id.in_(host_ids))
                        )
                    )
                )
            ).order_by(Comment.created_at.desc()).first()
    
    return latest_comment

# Keep original endpoint for backward compatibility
@router.get("/hosts/{host_id}/vulnerabilities/{vulnerability_id}/comments", response_model=List[CommentResponse])
async def get_host_vulnerability_comments(
    host_id: int,
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    # Use the batch endpoint internally for consistency
    request = CommentContextRequest(host_id=host_id, vulnerability_id=vulnerability_id)
    batch_result = await get_comments_batch(request, db, current_user)
    
    # Combine all comments and sort by priority
    all_comments = []
    all_comments.extend(batch_result.host_vulnerability_comments)
    all_comments.extend(batch_result.host_comments)
    all_comments.extend(batch_result.vulnerability_comments)
    
    return sorted(all_comments, key=lambda x: (x.comment_type, x.created_at), reverse=True)

# Update a comment
@router.put("/comments/{comment_id}", response_model=CommentResponse)
async def update_comment(
    comment_id: int,
    comment_update: CommentUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    # Only allow the creator to update their comment (or admin)
    if comment.created_by != current_user.username and current_user.role.name != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to update this comment")
    
    comment.content = comment_update.content
    comment.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(comment)
    
    return comment

# Delete a comment
@router.delete("/comments/{comment_id}")
async def delete_comment(
    comment_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    # Only allow the creator to delete their comment (or admin)
    if comment.created_by != current_user.username and current_user.role.name != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to delete this comment")
    
    db.delete(comment)
    db.commit()
    
    return {"message": "Comment deleted successfully"}

# Get all comments (for admin purposes)
@router.get("/comments", response_model=List[CommentResponse])
async def get_all_comments(
    skip: int = 0,
    limit: int = 100,
    owner: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    query = db.query(Comment)
    
    # Filter by owner if provided
    if owner:
        # Get all hosts owned by this owner
        host_ids = db.query(Host.id).filter(Host.server_owner == owner).all()
        host_ids = [host_id[0] for host_id in host_ids]
        
        if host_ids:
            # Get comments related to hosts owned by this owner
            query = query.filter(
                or_(
                    Comment.host_id.in_(host_ids),
                    # Also include vulnerability comments for vulns affecting this owner's hosts
                    and_(
                        Comment.comment_type == CommentType.VULNERABILITY.value,
                        Comment.vulnerability_id.in_(
                            db.query(Vulnerability.pluginid).join(Host, Host.id.in_(host_ids))
                        )
                    )
                )
            )
        else:
            # No hosts for this owner, return empty list
            return []
    
    comments = query.order_by(Comment.created_at.desc()).offset(skip).limit(limit).all()
    return comments

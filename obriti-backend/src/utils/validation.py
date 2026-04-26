"""
Input validation utilities for security
"""
import re
from typing import Any, Optional
from pydantic import BaseModel, validator, Field
from fastapi import HTTPException


class SearchRequest(BaseModel):
    """Validated search request"""
    search: str = Field("", max_length=100, description="Search term")
    page: int = Field(1, ge=1, le=1000, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Page size")
    
    @validator('search')
    def validate_search(cls, v):
        if v:
            # Remove potentially dangerous characters
            v = re.sub(r'[<>"\';\\]', '', v)
            # Limit length
            if len(v) > 100:
                raise ValueError('Search term too long')
        return v.strip()


class SeverityFilter(BaseModel):
    """Validated severity filter"""
    severity: str = Field("all", description="Severity filter")
    
    @validator('severity')
    def validate_severity(cls, v):
        allowed_values = ["all", "low", "medium", "high", "critical"]
        if v not in allowed_values:
            raise ValueError(f'Severity must be one of: {", ".join(allowed_values)}')
        return v


class StatusFilter(BaseModel):
    """Validated status filter"""
    status: str = Field("all", description="Status filter")
    
    @validator('status')
    def validate_status(cls, v):
        allowed_values = ["all", "active", "inactive", "pending"]
        if v not in allowed_values:
            raise ValueError(f'Status must be one of: {", ".join(allowed_values)}')
        return v


class HostCreateRequest(BaseModel):
    """Validated host creation request"""
    hostname: str = Field(..., min_length=1, max_length=255, description="Hostname")
    host_ip: str = Field(..., description="Host IP address")
    server_owner: Optional[str] = Field(None, max_length=255, description="Server owner")
    os_name: Optional[str] = Field(None, max_length=100, description="OS name")
    application_dependent: Optional[str] = Field(None, max_length=255, description="Application dependent")
    
    @validator('hostname')
    def validate_hostname(cls, v):
        if not v or not v.strip():
            raise ValueError('Hostname is required')
        # Remove potentially dangerous characters
        v = re.sub(r'[<>"\';\\]', '', v.strip())
        if len(v) > 255:
            raise ValueError('Hostname too long')
        return v
    
    @validator('host_ip')
    def validate_ip(cls, v):
        if not v or not v.strip():
            raise ValueError('IP address is required')
        # Basic IP validation
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_pattern, v.strip()):
            raise ValueError('Invalid IP address format')
        return v.strip()
    
    @validator('server_owner')
    def validate_server_owner(cls, v):
        if v:
            v = re.sub(r'[<>"\';\\]', '', v.strip())
            if len(v) > 255:
                raise ValueError('Server owner name too long')
        return v
    
    @validator('os_name')
    def validate_os_name(cls, v):
        if v:
            v = re.sub(r'[<>"\';\\]', '', v.strip())
            if len(v) > 100:
                raise ValueError('OS name too long')
        return v
    
    @validator('application_dependent')
    def validate_application_dependent(cls, v):
        if v:
            v = re.sub(r'[<>"\';\\]', '', v.strip())
            if len(v) > 255:
                raise ValueError('Application dependent field too long')
        return v


class CommentCreateRequest(BaseModel):
    """Validated comment creation request"""
    content: str = Field(..., min_length=1, max_length=2000, description="Comment content")
    comment_type: str = Field(..., description="Comment type")
    vulnerability_id: Optional[int] = Field(None, description="Vulnerability ID")
    host_id: Optional[int] = Field(None, description="Host ID")
    
    @validator('content')
    def validate_content(cls, v):
        if not v or not v.strip():
            raise ValueError('Comment content is required')
        # Remove potentially dangerous characters but allow some HTML
        v = re.sub(r'[<>"\';\\]', '', v.strip())
        if len(v) > 2000:
            raise ValueError('Comment content too long')
        return v
    
    @validator('comment_type')
    def validate_comment_type(cls, v):
        allowed_values = ["vulnerability", "host", "host_vulnerability"]
        if v not in allowed_values:
            raise ValueError(f'Comment type must be one of: {", ".join(allowed_values)}')
        return v


def sanitize_string(input_string: str, max_length: int = 255) -> str:
    """Sanitize string input by removing dangerous characters"""
    if not input_string:
        return ""
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\';\\]', '', str(input_string))
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()


def validate_pagination(page: int, page_size: int) -> tuple[int, int]:
    """Validate and sanitize pagination parameters"""
    if page < 1:
        page = 1
    if page > 1000:
        page = 1000
    if page_size < 1:
        page_size = 20
    if page_size > 100:
        page_size = 100
    
    return page, page_size

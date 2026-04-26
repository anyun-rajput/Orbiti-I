"""
Rate limiting utilities for security
"""
import time
from typing import Dict, Optional
from fastapi import HTTPException, Request
from collections import defaultdict, deque
import threading


class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()
    
    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """Check if request is allowed based on rate limit"""
        now = time.time()
        
        with self.lock:
            # Clean old requests outside the window
            while self.requests[key] and self.requests[key][0] <= now - window_seconds:
                self.requests[key].popleft()
            
            # Check if we're under the limit
            if len(self.requests[key]) >= max_requests:
                return False
            
            # Add current request
            self.requests[key].append(now)
            return True
    
    def get_remaining_requests(self, key: str, max_requests: int, window_seconds: int) -> int:
        """Get remaining requests in current window"""
        now = time.time()
        
        with self.lock:
            # Clean old requests
            while self.requests[key] and self.requests[key][0] <= now - window_seconds:
                self.requests[key].popleft()
            
            return max(0, max_requests - len(self.requests[key]))


# Global rate limiter instance
rate_limiter = RateLimiter()


def get_client_ip(request: Request) -> str:
    """Get client IP address from request"""
    # Check for forwarded headers first
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to direct connection
    if hasattr(request.client, 'host'):
        return request.client.host
    
    return "unknown"


def check_rate_limit(
    request: Request,
    max_requests: int = 100,
    window_seconds: int = 60,
    key_prefix: str = "default"
) -> None:
    """Check rate limit and raise exception if exceeded"""
    client_ip = get_client_ip(request)
    key = f"{key_prefix}:{client_ip}"
    
    if not rate_limiter.is_allowed(key, max_requests, window_seconds):
        remaining = rate_limiter.get_remaining_requests(key, max_requests, window_seconds)
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "message": f"Too many requests. Try again in {window_seconds} seconds.",
                "retry_after": window_seconds,
                "remaining_requests": remaining
            }
        )


def login_rate_limit(request: Request) -> None:
    """Rate limit for login attempts"""
    check_rate_limit(request, max_requests=5, window_seconds=300, key_prefix="login")  # 5 attempts per 5 minutes


def api_rate_limit(request: Request) -> None:
    """Rate limit for general API calls"""
    check_rate_limit(request, max_requests=100, window_seconds=60, key_prefix="api")  # 100 requests per minute


def admin_rate_limit(request: Request) -> None:
    """Rate limit for admin operations"""
    check_rate_limit(request, max_requests=20, window_seconds=60, key_prefix="admin")  # 20 requests per minute

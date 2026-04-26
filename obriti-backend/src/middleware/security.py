"""
Security middleware for adding security headers and other security measures
"""
from fastapi import Request, Response
from fastapi.responses import JSONResponse
import time
import uuid


class SecurityMiddleware:
    """Middleware to add security headers and measures"""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope, receive)
        
        # Add request ID for tracking
        request_id = str(uuid.uuid4())
        scope["request_id"] = request_id
        
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                
                # Add security headers
                security_headers = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"x-xss-protection": b"1; mode=block",
                    b"referrer-policy": b"strict-origin-when-cross-origin",
                    b"x-request-id": request_id.encode(),
                    b"x-response-time": str(int(time.time() * 1000)).encode(),
                }
                
                # Add HSTS header for HTTPS
                if request.url.scheme == "https":
                    security_headers[b"strict-transport-security"] = b"max-age=31536000; includeSubDomains"
                
                # Add Content Security Policy
                csp = (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data: https:; "
                    "connect-src 'self'; "
                    "font-src 'self'; "
                    "object-src 'none'; "
                    "base-uri 'self'; "
                    "form-action 'self'"
                )
                security_headers[b"content-security-policy"] = csp.encode()
                
                # Add permissions policy
                permissions_policy = (
                    "geolocation=(), "
                    "microphone=(), "
                    "camera=(), "
                    "payment=(), "
                    "usb=(), "
                    "magnetometer=(), "
                    "gyroscope=(), "
                    "speaker=(), "
                    "vibrate=(), "
                    "fullscreen=(self), "
                    "sync-xhr=()"
                )
                security_headers[b"permissions-policy"] = permissions_policy.encode()
                
                # Merge with existing headers
                for key, value in security_headers.items():
                    if key not in headers:
                        headers[key] = value
                
                message["headers"] = list(headers.items())
            
            await send(message)
        
        await self.app(scope, receive, send_wrapper)


def add_security_headers(response: Response) -> Response:
    """Add security headers to a response"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Add HSTS if HTTPS
    if hasattr(response, 'url') and response.url and response.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    return response


def create_security_response(data: dict, status_code: int = 200) -> JSONResponse:
    """Create a JSONResponse with security headers"""
    response = JSONResponse(content=data, status_code=status_code)
    return add_security_headers(response)

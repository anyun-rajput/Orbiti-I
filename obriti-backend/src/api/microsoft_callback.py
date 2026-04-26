from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from services.db import get_db
from services.microsoft_sso_service import microsoft_sso_service
from services.auth import create_access_token
from datetime import timedelta
from typing import Optional
import urllib.parse
import os
from config.settings import Config

router = APIRouter()

def validate_frontend_url(url: str) -> bool:
    """Validate that the frontend URL is safe and not an external redirect"""
    if not url:
        return False
    
    # Only allow HTTPS in production
    if Config.ENVIRONMENT == "production" and not url.startswith("https://"):
        return False
    
    # Allow localhost and orbiti.fareportal.com domains
    allowed_domains = [
        "localhost",
        "127.0.0.1", 
        "orbiti.fareportal.com"
    ]
    
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]  # Remove port if present
        
        # Allow localhost with any port
        if domain in ["localhost", "127.0.0.1"]:
            return True
            
        # Allow specific domains
        if domain in allowed_domains:
            return True
            
        # In development, allow more domains
        if Config.ENVIRONMENT == "development":
            return True
            
    except:
        pass
    
    return False

@router.get("/microsoft/login")
def microsoft_login_redirect(
    state: Optional[str] = None, 
    myapps: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Direct Microsoft login route that redirects to Microsoft OAuth"""
    
    # Add MyApps state if coming from MyApps
    if myapps == "true" or myapps == "1":
        state = f"myapps_{state}" if state else "myapps"
    
    # Get the Microsoft auth URL
    auth_url = microsoft_sso_service.get_auth_url(db, state)
    
    if not auth_url:
        # If Microsoft SSO is not configured, redirect to frontend with error
        return RedirectResponse(
            url=f"{Config.FRONTEND_URL}/login?error=microsoft_not_configured&error_description=Microsoft%20SSO%20is%20not%20configured",
            status_code=302
        )
    
    # Redirect directly to Microsoft OAuth login
    return RedirectResponse(url=auth_url, status_code=302)

@router.get("/microsoft/callback")
def microsoft_callback(
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
    admin_consent: Optional[str] = Query(None),
    myapps: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Handle Microsoft SSO callback for both direct login and MyApps"""
    
    # Detect if this is coming from MyApps
    is_myapps = (
        myapps == "true" or 
        (state and state.startswith("myapps_")) or
        (state == "myapps")
    )
    
    # Log all parameters for debugging
    print(f"Microsoft callback received - code: {code[:10] if code else None}..., state: {state}, error: {error}, admin_consent: {admin_consent}, myapps: {is_myapps}")
    
    # Check for OAuth errors
    if error:
        error_msg = error_description or f"OAuth error: {error}"
        print(f"OAuth error in callback: {error} - {error_msg}")
        encoded_error = urllib.parse.quote(error_msg)
        
        # Add MyApps context to error if applicable
        error_prefix = "myapps_" if is_myapps else ""
        return RedirectResponse(
            url=f"{Config.FRONTEND_URL}/login?error={error_prefix}{error}&error_description={encoded_error}",
            status_code=302
        )
    
    if not code:
        # Redirect to frontend login with error
        error_prefix = "myapps_" if is_myapps else ""
        error_desc = "No authorization code received from MyApps" if is_myapps else "No authorization code received"
        return RedirectResponse(
            url=f"{Config.FRONTEND_URL}/login?error={error_prefix}no_code&error_description={urllib.parse.quote(error_desc)}",
            status_code=302
        )
    
    try:
        print(f"Microsoft callback received: code={code[:10] if code else None}..., state={state}")
        
        # Exchange code for token first to get detailed error info
        token_result = microsoft_sso_service.exchange_code_for_token(code, db)
        
        if not token_result:
            # Redirect to frontend login with generic error if no specific error available
            return RedirectResponse(
                url=f"{Config.FRONTEND_URL}/login?error=auth_failed&error_description=Microsoft%20authentication%20failed%20-%20unable%20to%20exchange%20authorization%20code",
                status_code=302
            )
        
        # Check if token_result contains an error
        if "error" in token_result:
            error_code = token_result.get('error', 'unknown_error')
            error_desc = token_result.get('error_description', 'Microsoft authentication failed')
            
            # Create user-friendly error messages based on common error codes
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
            
            encoded_error = urllib.parse.quote(friendly_error)
            return RedirectResponse(
                url=f"{Config.FRONTEND_URL}/login?error={error_code}&error_description={encoded_error}",
                status_code=302
            )
        
        # If token exchange succeeded, complete the authentication flow
        print("Token exchange successful, getting user info from Microsoft Graph...")
        
        # Get user info from Microsoft Graph
        user_info = microsoft_sso_service.get_user_info(token_result['access_token'])
        if not user_info:
            return RedirectResponse(
                url=f"{Config.FRONTEND_URL}/login?error=graph_api_failed&error_description=Failed%20to%20retrieve%20user%20information%20from%20Microsoft%20Graph",
                status_code=302
            )
        
        # Create or update user in database
        print(f"Creating/updating user for: {user_info.get('displayName', 'Unknown')} ({user_info.get('mail', 'No email')})")
        user = microsoft_sso_service.create_or_update_user(user_info, db)
        if not user:
            return RedirectResponse(
                url=f"{Config.FRONTEND_URL}/login?error=user_creation_failed&error_description=Failed%20to%20create%20or%20update%20user%20account",
                status_code=302
            )
        
        # Generate JWT token for our application
        print(f"Generating JWT token for user: {user.username}")
        access_token = create_access_token(
            data={"sub": user.username},
            expires_delta=timedelta(minutes=60)
        )
        
        result = {
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
        
        # Redirect to frontend with success and token
        access_token = result["access_token"]
        user_info = result["user"]
        username = urllib.parse.quote(user_info['username'])
        
        # Redirect to frontend callback handler with token
        myapps_param = "&myapps=true" if is_myapps else ""
        return RedirectResponse(
            url=f"{Config.FRONTEND_URL}/auth/microsoft/callback?token={access_token}&user={username}&success=true{myapps_param}",
            status_code=302
        )
        
    except Exception as e:
        print(f"Microsoft callback error: {e}")
        error_msg = urllib.parse.quote(str(e))
        # Redirect to frontend login with error
        return RedirectResponse(
            url=f"{Config.FRONTEND_URL}/login?error=server_error&error_description={error_msg}",
            status_code=302
        )


@router.get("/microsoft/diagnostics")
def microsoft_diagnostics(db: Session = Depends(get_db)):
    """Diagnostic endpoint to help troubleshoot MyApps issues"""
    
    # Get configuration from database
    config_data = microsoft_sso_service._get_dynamic_config(db)
    
    diagnostics = {
        "azure_ad_config": {
            "client_id": config_data.get('clientId', 'Not configured')[:8] + "..." if config_data and config_data.get('clientId') else "Not configured",
            "tenant_id": config_data.get('tenantId', 'Not configured') if config_data else "Not configured",
            "redirect_uri": config_data.get('redirectUri', 'Not configured') if config_data else "Not configured",
            "scopes": config_data.get('scopes', ['User.Read']) if config_data else ['User.Read'],
            "is_configured": config_data is not None
        },
        "database_config": {
            "integration_exists": config_data is not None,
            "integration_enabled": config_data.get('enabled', False) if config_data else False,
            "config_keys": list(config_data.keys()) if config_data else []
        },
        "endpoints": {
            "callback": "/microsoft/callback (handles both direct login and MyApps)",
            "diagnostics": "/microsoft/diagnostics"
        },
        "recommendations": []
    }
    
    # Add recommendations based on configuration
    if not config_data:
        diagnostics["recommendations"].append("Configure Microsoft SSO in database (IntegrationConfig table)")
    
    if config_data and not config_data.get('enabled', False):
        diagnostics["recommendations"].append("Enable Microsoft SSO integration in database")
    
    if config_data and not config_data.get('clientId'):
        diagnostics["recommendations"].append("Set clientId in Microsoft SSO configuration")
    
    if config_data and not config_data.get('clientSecret'):
        diagnostics["recommendations"].append("Set clientSecret in Microsoft SSO configuration")
    
    if config_data and not config_data.get('redirectUri'):
        diagnostics["recommendations"].append("Set redirectUri in Microsoft SSO configuration")
    
    if config_data and "localhost" in config_data.get('redirectUri', ''):
        diagnostics["recommendations"].append("Update redirect URI to production domain for MyApps")
    
    return JSONResponse(content=diagnostics)

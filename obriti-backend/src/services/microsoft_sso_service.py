import msal
import requests
from typing import Optional, Dict, Any
from models.scan import IntegrationConfig
from sqlalchemy.orm import Session
import json
from models.scan import User, Role
from utils.auth_utils import create_access_token
from datetime import timedelta

class MicrosoftSSOService:
    """Service for handling Microsoft SSO authentication"""
    
    def __init__(self):
        # Default configuration - will be overridden by database config
        self.default_scope = ["User.Read"]
        self.graph_endpoint = "https://graph.microsoft.com/v1.0/me"
    
    def _get_dynamic_config(self, db: Session) -> Optional[Dict[str, Any]]:
        """Get Microsoft SSO configuration from database"""
        integration = db.query(IntegrationConfig).filter(
            IntegrationConfig.integration_type == 'microsoft_sso',
            IntegrationConfig.enabled == True
        ).first()
        
        if integration and integration.config_data:
            return json.loads(integration.config_data)
        return None
    
    def _create_msal_app(self, config_data: Dict[str, Any]) -> Optional[msal.ConfidentialClientApplication]:
        """Create MSAL application with dynamic configuration"""
        try:
            client_id = config_data.get('clientId')
            tenant_id = config_data.get('tenantId', 'common')
            client_secret = config_data.get('clientSecret')  # Use database client secret
            
            if not client_id or not client_secret:
                print(f"Missing client_id or client_secret: client_id={bool(client_id)}, client_secret={bool(client_secret)}")
                return None
                
            authority = f"https://login.microsoftonline.com/{tenant_id}"
            print(f"Creating MSAL app with authority: {authority}, client_id: {client_id[:8]}...")
            
            return msal.ConfidentialClientApplication(
                client_id=client_id,
                client_credential=client_secret,
                authority=authority,
                # Add token cache if needed
                token_cache=None
            )
        except Exception as e:
            print(f"Error creating MSAL app: {e}")
            return None
    
    def get_auth_url(self, db: Session, state: str = None) -> Optional[str]:
        """Generate Microsoft SSO authorization URL using database configuration"""
        config_data = self._get_dynamic_config(db)
        
        if config_data:
            app = self._create_msal_app(config_data)
            if app:
                redirect_uri = config_data.get('redirectUri')
                scopes = config_data.get('scopes', self.default_scope)
                auth_url = app.get_authorization_request_url(
                    scopes=scopes,
                    redirect_uri=redirect_uri,
                    state=state
                )
                return auth_url
            
        return None
    
    def exchange_code_for_token(self, authorization_code: str, db: Session) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access token using database configuration"""
        config_data = self._get_dynamic_config(db)
        
        if config_data:
            app = self._create_msal_app(config_data)
            if app:
                redirect_uri = config_data.get('redirectUri')
                scopes = config_data.get('scopes', self.default_scope)
                print(f"Token exchange params: code={authorization_code[:10]}..., scopes={scopes}, redirect_uri={redirect_uri}")
                result = app.acquire_token_by_authorization_code(
                    code=authorization_code,
                    scopes=scopes,
                    redirect_uri=redirect_uri
                )
                print(f"MSAL token exchange result: {result}")  # Debug logging
                if "access_token" in result:
                    return result
                elif "error" in result:
                    print(f"MSAL error: {result.get('error')} - {result.get('error_description')}")
                    # Return error details for better frontend feedback
                    return {
                        "error": result.get('error'),
                        "error_description": result.get('error_description'),
                        "error_codes": result.get('error_codes', [])
                    }
                
        return None
    
    def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user information from Microsoft Graph API"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.get(self.graph_endpoint, headers=headers)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error fetching user info: {e}")
        
        return None
    
    def create_or_update_user(self, user_info: Dict[str, Any], db: Session) -> Optional[User]:
        """Create or update user from Microsoft SSO info"""
        try:
            email = user_info.get('mail') or user_info.get('userPrincipalName')
            if not email:
                return None
            
            external_id = user_info.get('id')
            display_name = user_info.get('displayName', '')
            given_name = user_info.get('givenName', '')
            surname = user_info.get('surname', '')
            
            # Check if user already exists by email or external_id
            existing_user = db.query(User).filter(
                (User.email == email) | (User.external_id == external_id)
            ).first()
            
            if existing_user:
                # Update existing user with latest info
                existing_user.first_name = given_name
                existing_user.last_name = surname
                existing_user.auth_provider = 'microsoft'
                existing_user.external_id = external_id
                existing_user.is_active = True
                db.commit()
                db.refresh(existing_user)
                return existing_user
            else:
                # Create new user with org_team role by default
                org_team_role = db.query(Role).filter(Role.name == 'org_team').first()
                if not org_team_role:
                    return None
                
                # Generate username from email
                username = email.split('@')[0]
                counter = 1
                original_username = username
                while db.query(User).filter(User.username == username).first():
                    username = f"{original_username}{counter}"
                    counter += 1
                
                new_user = User(
                    username=username,
                    email=email,
                    first_name=given_name,
                    last_name=surname,
                    auth_provider='microsoft',
                    external_id=external_id,
                    role_id=org_team_role.id,
                    is_active=True,
                    hashed_password=None  # No password for SSO users
                )
                
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                return new_user
                
        except Exception as e:
            print(f"Error creating/updating user: {e}")
            db.rollback()
            return None
    
    def authenticate_user(self, authorization_code: str, db: Session) -> Optional[Dict[str, Any]]:
        """Complete Microsoft SSO authentication flow"""
        # Exchange code for token
        token_result = self.exchange_code_for_token(authorization_code, db)
        if not token_result:
            return None
        
        # Get user info from Microsoft Graph
        user_info = self.get_user_info(token_result['access_token'])
        if not user_info:
            return None
        
        # Create or update user in database
        user = self.create_or_update_user(user_info, db)
        if not user:
            return None
        
        # Generate JWT token for our application
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

# Global instance
microsoft_sso_service = MicrosoftSSOService()

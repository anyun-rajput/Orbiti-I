import os
from typing import Optional

class MicrosoftSSOConfig:
    """Microsoft SSO configuration settings"""
    
    def __init__(self):
        # These should be set as environment variables in production
        self.CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID", "your-client-id-here")
        self.CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET", "your-client-secret-here")
        self.TENANT_ID = os.getenv("MICROSOFT_TENANT_ID", "common")  # 'common' for multi-tenant
        self.REDIRECT_URI = os.getenv("MICROSOFT_REDIRECT_URI", "http://localhost:8000/microsoft/callback")
        
        # MyApps uses the same redirect URI as the main callback
        self.MYAPPS_REDIRECT_URI = self.REDIRECT_URI
        
        # Microsoft Graph API endpoints
        self.AUTHORITY = f"https://login.microsoftonline.com/{self.TENANT_ID}"
        self.SCOPE = ["User.Read"]  # Remove reserved scopes: profile, openid, email are automatically included
        
        # Graph API endpoint for user info
        self.GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0/me"
        
        # MyApps specific configuration
        self.MYAPPS_ENABLED = os.getenv("MICROSOFT_MYAPPS_ENABLED", "true").lower() == "true"
    
    def is_configured(self) -> bool:
        """Check if Microsoft SSO is properly configured"""
        return (
            self.CLIENT_ID != "your-client-id-here" and
            self.CLIENT_SECRET != "your-client-secret-here" and
            self.CLIENT_ID and
            self.CLIENT_SECRET
        )

# Global instance
microsoft_sso_config = MicrosoftSSOConfig()

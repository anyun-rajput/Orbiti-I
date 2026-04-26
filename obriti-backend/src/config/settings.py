"""
Secure configuration management using environment variables
This module loads all configuration from environment variables with sensible defaults
"""

import os
from dotenv import load_dotenv
from typing import Optional

# Load environment variables from .env file
load_dotenv()


class Config:
    """Base configuration class"""

    # Database Configuration
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        ""
    )

    # JWT Secret Key - MUST be set in production
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "change-me-in-production-use-a-strong-random-string"
    )
    
    # Validate SECRET_KEY is not default in non-development environments
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    if ENVIRONMENT == "production" and SECRET_KEY == "change-me-in-production-use-a-strong-random-string":
        raise ValueError("SECRET_KEY must be set to a strong value in production!")

    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

    # SMTP Configuration
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "localhost")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "noreply@example.com")

    # Nessus Configuration
    NESSUS_API_URL: str = os.getenv("NESSUS_API_URL", "https://nessus.example.com:8834")
    NESSUS_ACCESS_KEY: str = os.getenv("NESSUS_ACCESS_KEY", "")
    NESSUS_SECRET_KEY: str = os.getenv("NESSUS_SECRET_KEY", "")

    # API Tokens
    API_ACCESS_TOKEN: str = os.getenv("API_ACCESS_TOKEN", "")

    # Azure/Microsoft SSO Configuration
    AZURE_CLIENT_ID: str = os.getenv("AZURE_CLIENT_ID", "")
    AZURE_CLIENT_SECRET: str = os.getenv("AZURE_CLIENT_SECRET", "")
    AZURE_TENANT_ID: str = os.getenv("AZURE_TENANT_ID", "")

    # Admin User Configuration
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "")
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@example.com")

    # Application Settings
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Security
    ALLOWED_HOSTS: list = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    CORS_ORIGINS: list = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

    # Frontend URL for redirects
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "https://orbiti.fareportal.com")
    
    # API Base URL for internal API calls
    API_BASE_URL: str = os.getenv("API_BASE_URL", "https://orbiti.fareportal.com:7000")
    
    # Validate FRONTEND_URL
    if FRONTEND_URL:
        from urllib.parse import urlparse
        parsed = urlparse(FRONTEND_URL)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"FRONTEND_URL must be a valid URL: {FRONTEND_URL}")
        if ENVIRONMENT == "production" and parsed.scheme != "https":
            raise ValueError(f"FRONTEND_URL must use HTTPS in production: {FRONTEND_URL}")

    # Elasticsearch Configuration (optional)
    ELASTICSEARCH_HOST: str = os.getenv("ELASTICSEARCH_HOST", "localhost")
    ELASTICSEARCH_PORT: int = int(os.getenv("ELASTICSEARCH_PORT", "9200"))
    ELASTICSEARCH_USERNAME: Optional[str] = os.getenv("ELASTICSEARCH_USERNAME", None)
    ELASTICSEARCH_PASSWORD: Optional[str] = os.getenv("ELASTICSEARCH_PASSWORD", None)

    # Database Pool Configuration
    DB_POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", "20"))
    DB_MAX_OVERFLOW: int = int(os.getenv("DB_MAX_OVERFLOW", "30"))
    DB_POOL_RECYCLE: int = int(os.getenv("DB_POOL_RECYCLE", "3600"))

    @classmethod
    def validate_production_settings(cls) -> bool:
        """Validate critical settings for production environment"""
        if cls.ENVIRONMENT == "production":
            critical_vars = [
                ("DATABASE_URL", cls.DATABASE_URL),
                ("SECRET_KEY", cls.SECRET_KEY),
            ]
            
            for var_name, var_value in critical_vars:
                if not var_value or var_value.startswith("your-") or var_value == "change-me":
                    raise ValueError(
                        f"Critical setting {var_name} is not properly configured for production!"
                    )
        
        return True


# Create a singleton instance for use throughout the application
config = Config()

__all__ = ["config", "Config"]

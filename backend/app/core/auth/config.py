"""
Authentication Configuration

Defines configuration settings for AWS Cognito and Auth0 authentication providers.
"""

import os
from typing import Optional, Dict, Any
from pydantic import BaseSettings, validator


class AuthConfig(BaseSettings):
    """Authentication configuration settings."""
    
    # Provider selection
    AUTH_PROVIDER: str = "local"  # "local", "cognito", or "auth0"
    
    # AWS Cognito Configuration
    AWS_REGION: str = "us-east-1"
    COGNITO_USER_POOL_ID: Optional[str] = None
    COGNITO_CLIENT_ID: Optional[str] = None
    COGNITO_CLIENT_SECRET: Optional[str] = None
    COGNITO_DOMAIN: Optional[str] = None
    COGNITO_REDIRECT_URI: Optional[str] = None
    COGNITO_LOGOUT_URI: Optional[str] = None
    
    # Auth0 Configuration
    AUTH0_DOMAIN: Optional[str] = None
    AUTH0_CLIENT_ID: Optional[str] = None
    AUTH0_CLIENT_SECRET: Optional[str] = None
    AUTH0_AUDIENCE: Optional[str] = None
    AUTH0_WEBHOOK_SECRET: Optional[str] = None
    
    # JWT Configuration (for local auth)
    SECRET_KEY: str = "your-secret-key-here"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Security Configuration
    ALLOWED_HOSTS: str = "localhost,127.0.0.1"
    ALLOWED_ORIGINS: str = "http://localhost:3000,https://localhost:3000"
    
    # Database Configuration
    DATABASE_URL: str = "sqlite:///./app.db"
    
    class Config:
        env_file = ".env"
        case_sensitive = True
    
    @validator("AUTH_PROVIDER")
    def validate_auth_provider(cls, v):
        """Validate authentication provider."""
        allowed_providers = ["local", "cognito", "auth0"]
        if v not in allowed_providers:
            raise ValueError(f"AUTH_PROVIDER must be one of {allowed_providers}")
        return v
    
    @validator("COGNITO_USER_POOL_ID", "COGNITO_CLIENT_ID")
    def validate_cognito_config(cls, v, values):
        """Validate Cognito configuration when provider is cognito."""
        if values.get("AUTH_PROVIDER") == "cognito" and not v:
            raise ValueError(f"Cognito configuration required when AUTH_PROVIDER is 'cognito'")
        return v
    
    @validator("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET")
    def validate_auth0_config(cls, v, values):
        """Validate Auth0 configuration when provider is auth0."""
        if values.get("AUTH_PROVIDER") == "auth0" and not v:
            raise ValueError(f"Auth0 configuration required when AUTH_PROVIDER is 'auth0'")
        return v
    
    def get_cognito_config(self) -> Dict[str, Any]:
        """Get Cognito configuration."""
        if self.AUTH_PROVIDER != "cognito":
            return {}
        
        return {
            "region": self.AWS_REGION,
            "user_pool_id": self.COGNITO_USER_POOL_ID,
            "client_id": self.COGNITO_CLIENT_ID,
            "client_secret": self.COGNITO_CLIENT_SECRET,
            "domain": self.COGNITO_DOMAIN,
            "redirect_uri": self.COGNITO_REDIRECT_URI,
            "logout_uri": self.COGNITO_LOGOUT_URI
        }
    
    def get_auth0_config(self) -> Dict[str, Any]:
        """Get Auth0 configuration."""
        if self.AUTH_PROVIDER != "auth0":
            return {}
        
        return {
            "domain": self.AUTH0_DOMAIN,
            "client_id": self.AUTH0_CLIENT_ID,
            "client_secret": self.AUTH0_CLIENT_SECRET,
            "audience": self.AUTH0_AUDIENCE,
            "webhook_secret": self.AUTH0_WEBHOOK_SECRET
        }
    
    def get_jwt_config(self) -> Dict[str, Any]:
        """Get JWT configuration for local auth."""
        return {
            "secret_key": self.SECRET_KEY,
            "algorithm": self.ALGORITHM,
            "access_token_expire_minutes": self.ACCESS_TOKEN_EXPIRE_MINUTES
        }
    
    def is_provider_configured(self, provider: str) -> bool:
        """Check if a specific provider is properly configured."""
        if provider == "cognito":
            return all([
                self.COGNITO_USER_POOL_ID,
                self.COGNITO_CLIENT_ID,
                self.COGNITO_DOMAIN
            ])
        elif provider == "auth0":
            return all([
                self.AUTH0_DOMAIN,
                self.AUTH0_CLIENT_ID,
                self.AUTH0_CLIENT_SECRET
            ])
        elif provider == "local":
            return self.SECRET_KEY != "your-secret-key-here"
        return False
    
    def get_allowed_hosts(self) -> list:
        """Get list of allowed hosts."""
        return [host.strip() for host in self.ALLOWED_HOSTS.split(",")]
    
    def get_allowed_origins(self) -> list:
        """Get list of allowed origins for CORS."""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",")]


# Global configuration instance
auth_config = AuthConfig()


def get_auth_config() -> AuthConfig:
    """Get authentication configuration."""
    return auth_config


def validate_auth_configuration() -> Dict[str, Any]:
    """Validate authentication configuration and return status."""
    config = get_auth_config()
    
    validation_result = {
        "provider": config.AUTH_PROVIDER,
        "configured": config.is_provider_configured(config.AUTH_PROVIDER),
        "errors": [],
        "warnings": []
    }
    
    # Check provider-specific configuration
    if config.AUTH_PROVIDER == "cognito":
        cognito_config = config.get_cognito_config()
        missing_fields = [k for k, v in cognito_config.items() if not v and k not in ["client_secret", "redirect_uri", "logout_uri"]]
        if missing_fields:
            validation_result["errors"].append(f"Missing Cognito configuration: {', '.join(missing_fields)}")
    
    elif config.AUTH_PROVIDER == "auth0":
        auth0_config = config.get_auth0_config()
        missing_fields = [k for k, v in auth0_config.items() if not v and k != "webhook_secret"]
        if missing_fields:
            validation_result["errors"].append(f"Missing Auth0 configuration: {', '.join(missing_fields)}")
    
    elif config.AUTH_PROVIDER == "local":
        if config.SECRET_KEY == "your-secret-key-here":
            validation_result["warnings"].append("Using default SECRET_KEY - change in production")
    
    # Check database configuration
    if not config.DATABASE_URL:
        validation_result["errors"].append("DATABASE_URL not configured")
    
    # Check security configuration
    if "localhost" in config.get_allowed_hosts() and "localhost" in config.get_allowed_origins():
        validation_result["warnings"].append("Using localhost in production - consider restricting hosts and origins")
    
    return validation_result


def get_environment_template() -> str:
    """Get environment variables template."""
    return """# Authentication Configuration
# Choose your authentication provider: local, cognito, or auth0
AUTH_PROVIDER=local

# AWS Cognito Configuration (required if AUTH_PROVIDER=cognito)
AWS_REGION=us-east-1
COGNITO_USER_POOL_ID=your-user-pool-id
COGNITO_CLIENT_ID=your-client-id
COGNITO_CLIENT_SECRET=your-client-secret
COGNITO_DOMAIN=your-domain.auth.us-east-1.amazoncognito.com
COGNITO_REDIRECT_URI=http://localhost:3000/auth/callback
COGNITO_LOGOUT_URI=http://localhost:3000

# Auth0 Configuration (required if AUTH_PROVIDER=auth0)
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_AUDIENCE=your-api-identifier
AUTH0_WEBHOOK_SECRET=your-webhook-secret

# JWT Configuration (for local auth)
SECRET_KEY=your-super-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Security Configuration
ALLOWED_HOSTS=localhost,127.0.0.1
ALLOWED_ORIGINS=http://localhost:3000,https://localhost:3000

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost/dbname
""" 
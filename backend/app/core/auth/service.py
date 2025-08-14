"""
Unified Authentication Service

Provides a unified interface for authentication using either AWS Cognito or Auth0,
integrating seamlessly with the RBAC system.
"""

from typing import Optional, Dict, Any, Union
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import os

from .cognito import cognito_auth
from .auth0 import auth0_auth
from ..rbac.models import User
from ..rbac.roles import RoleManager
from ..rbac.permissions import PermissionManager
from ..database import get_db_session

# HTTP Bearer token security
security = HTTPBearer()


class AuthProvider:
    """Enum for authentication providers."""
    COGNITO = "cognito"
    AUTH0 = "auth0"
    LOCAL = "local"


class UnifiedAuthService:
    """Unified authentication service supporting multiple providers."""
    
    def __init__(self):
        self.provider = os.getenv("AUTH_PROVIDER", "local").lower()
        self.auth_service = self._get_auth_service()
    
    def _get_auth_service(self):
        """Get the appropriate authentication service based on configuration."""
        if self.provider == AuthProvider.COGNITO:
            return cognito_auth
        elif self.provider == AuthProvider.AUTH0:
            return auth0_auth
        else:
            return None  # Local authentication
    
    def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db_session)) -> User:
        """Get the current authenticated user from any provider."""
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        token = credentials.credentials
        
        try:
            if self.provider == AuthProvider.COGNITO:
                return self._get_cognito_user(token, db)
            elif self.provider == AuthProvider.AUTH0:
                return self._get_auth0_user(token, db)
            else:
                return self._get_local_user(token, db)
                
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    def _get_cognito_user(self, token: str, db: Session) -> User:
        """Get user from Cognito token."""
        try:
            # Verify token with Cognito
            payload = cognito_auth.verify_token(token)
            
            # Get user info from Cognito
            user_info = cognito_auth.get_user_info(token)
            
            # Sync with local RBAC system
            user = cognito_auth.sync_user_with_rbac(db, user_info)
            
            return user
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid Cognito token: {str(e)}"
            )
    
    def _get_auth0_user(self, token: str, db: Session) -> User:
        """Get user from Auth0 token."""
        try:
            # Verify token with Auth0
            payload = auth0_auth.verify_token(token)
            
            # Get user info from Auth0
            user_info = auth0_auth.get_user_info(token)
            
            # Sync with local RBAC system
            user = auth0_auth.sync_user_with_rbac(db, user_info)
            
            return user
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid Auth0 token: {str(e)}"
            )
    
    def _get_local_user(self, token: str, db: Session) -> User:
        """Get user from local JWT token."""
        try:
            # This would use your existing local JWT authentication
            # For now, we'll raise an error indicating local auth is not configured
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Local authentication not configured"
            )
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid local token: {str(e)}"
            )
    
    def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user with the configured provider."""
        if self.provider == AuthProvider.COGNITO:
            return cognito_auth.authenticate_user(username, password)
        elif self.provider == AuthProvider.AUTH0:
            # Auth0 doesn't support direct username/password auth in this way
            # You would typically use the OAuth flow instead
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Direct authentication not supported for Auth0. Use OAuth flow instead."
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Local authentication not configured"
            )
    
    def create_user(self, email: str, password: str, **kwargs) -> Dict[str, Any]:
        """Create user with the configured provider."""
        if self.provider == AuthProvider.COGNITO:
            return cognito_auth.create_user(email, password, **kwargs)
        elif self.provider == AuthProvider.AUTH0:
            return auth0_auth.create_user(email, password, **kwargs)
        else:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Local authentication not configured"
            )
    
    def get_login_url(self, redirect_uri: str) -> str:
        """Get login URL for the configured provider."""
        if self.provider == AuthProvider.COGNITO:
            return cognito_auth.get_cognito_login_url()
        elif self.provider == AuthProvider.AUTH0:
            return auth0_auth.get_auth0_login_url(redirect_uri)
        else:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Local authentication not configured"
            )
    
    def get_logout_url(self, return_to: str = None) -> str:
        """Get logout URL for the configured provider."""
        if self.provider == AuthProvider.COGNITO:
            return cognito_auth.get_cognito_logout_url()
        elif self.provider == AuthProvider.AUTH0:
            return auth0_auth.get_auth0_logout_url(return_to or "/")
        else:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Local authentication not configured"
            )
    
    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token with the configured provider."""
        if self.provider == AuthProvider.COGNITO:
            return cognito_auth.refresh_token(refresh_token)
        elif self.provider == AuthProvider.AUTH0:
            return auth0_auth.refresh_access_token(refresh_token)
        else:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Local authentication not configured"
            )
    
    def get_provider_info(self) -> Dict[str, Any]:
        """Get information about the configured authentication provider."""
        return {
            "provider": self.provider,
            "configured": self.auth_service is not None,
            "features": self._get_provider_features()
        }
    
    def _get_provider_features(self) -> Dict[str, bool]:
        """Get features available for the configured provider."""
        if self.provider == AuthProvider.COGNITO:
            return {
                "username_password_auth": True,
                "oauth_flow": True,
                "social_login": True,
                "mfa": True,
                "user_management": True,
                "role_management": True
            }
        elif self.provider == AuthProvider.AUTH0:
            return {
                "username_password_auth": True,
                "oauth_flow": True,
                "social_login": True,
                "mfa": True,
                "user_management": True,
                "role_management": True,
                "rules_hooks": True,
                "organizations": True
            }
        else:
            return {
                "username_password_auth": False,
                "oauth_flow": False,
                "social_login": False,
                "mfa": False,
                "user_management": False,
                "role_management": False
            }


# Global unified auth service instance
unified_auth = UnifiedAuthService()


# Dependency functions for easy use in FastAPI endpoints
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db_session)) -> User:
    """Get current authenticated user - use this in your endpoints."""
    return unified_auth.get_current_user(credentials, db)


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get current active user."""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def get_auth_provider_info() -> Dict[str, Any]:
    """Get information about the configured authentication provider."""
    return unified_auth.get_provider_info() 
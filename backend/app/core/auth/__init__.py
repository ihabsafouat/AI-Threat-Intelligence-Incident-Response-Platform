"""
Authentication Module

Provides authentication services for AWS Cognito, Auth0, and local authentication.
"""

from .service import (
    UnifiedAuthService,
    unified_auth,
    get_current_user,
    get_current_active_user,
    get_auth_provider_info,
    AuthProvider
)

from .cognito import CognitoAuth, cognito_auth
from .auth0 import Auth0Auth, auth0_auth

__all__ = [
    "UnifiedAuthService",
    "unified_auth",
    "get_current_user",
    "get_current_active_user",
    "get_auth_provider_info",
    "AuthProvider",
    "CognitoAuth",
    "cognito_auth",
    "Auth0Auth",
    "auth0_auth"
] 
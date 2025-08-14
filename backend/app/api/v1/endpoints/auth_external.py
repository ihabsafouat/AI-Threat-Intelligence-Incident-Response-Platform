"""
External Authentication API Endpoints

Provides endpoints for AWS Cognito and Auth0 authentication integration.
"""

from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import secrets

from app.core.auth.service import unified_auth, get_current_user, get_auth_provider_info
from app.core.database import get_db_session
from app.core.rbac.models import User

router = APIRouter(prefix="/auth/external", tags=["external-authentication"])


# OAuth Flow Endpoints
@router.get("/login")
async def external_login(
    redirect_uri: str,
    state: Optional[str] = None
):
    """Get external login URL for the configured provider."""
    try:
        # Generate state if not provided
        if not state:
            state = secrets.token_urlsafe(32)
        
        login_url = unified_auth.get_login_url(redirect_uri)
        
        if not login_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="External login not configured"
            )
        
        return {
            "login_url": login_url,
            "state": state,
            "provider": unified_auth.provider
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate login URL: {str(e)}"
        )


@router.get("/callback")
async def oauth_callback(
    code: str,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    redirect_uri: str = None
):
    """Handle OAuth callback from external provider."""
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth error: {error} - {error_description}"
        )
    
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code not provided"
        )
    
    try:
        # Exchange code for tokens
        tokens = unified_auth.refresh_token(code)
        
        return {
            "message": "OAuth callback successful",
            "access_token": tokens.get("access_token"),
            "id_token": tokens.get("id_token"),
            "refresh_token": tokens.get("refresh_token"),
            "expires_in": tokens.get("expires_in"),
            "token_type": tokens.get("token_type")
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OAuth callback failed: {str(e)}"
        )


@router.get("/logout")
async def external_logout(
    return_to: str = "/"
):
    """Get external logout URL."""
    try:
        logout_url = unified_auth.get_logout_url(return_to)
        
        if not logout_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="External logout not configured"
            )
        
        return {
            "logout_url": logout_url,
            "return_to": return_to,
            "provider": unified_auth.provider
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate logout URL: {str(e)}"
        )


# Direct Authentication Endpoints (for Cognito)
@router.post("/login/direct")
async def direct_login(
    username: str,
    password: str
):
    """Direct username/password login (Cognito only)."""
    try:
        result = unified_auth.authenticate_user(username, password)
        
        return {
            "message": "Authentication successful",
            "result": result,
            "provider": unified_auth.provider
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication failed: {str(e)}"
        )


@router.post("/login/new-password")
async def complete_new_password(
    username: str,
    new_password: str,
    session: str
):
    """Complete new password challenge (Cognito only)."""
    try:
        if unified_auth.provider != "cognito":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password challenge only supported for Cognito"
            )
        
        from app.core.auth.cognito import cognito_auth
        result = cognito_auth.complete_new_password_challenge(username, new_password, session)
        
        return {
            "message": "New password set successfully",
            "result": result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password change failed: {str(e)}"
        )


# Token Management
@router.post("/refresh")
async def refresh_token(
    refresh_token: str
):
    """Refresh access token."""
    try:
        result = unified_auth.refresh_token(refresh_token)
        
        return {
            "message": "Token refreshed successfully",
            "result": result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token refresh failed: {str(e)}"
        )


# User Management
@router.post("/users")
async def create_external_user(
    email: str,
    password: str,
    name: Optional[str] = None,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Create user in external provider."""
    try:
        # Check if user has permission to create users
        if not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to create users"
            )
        
        result = unified_auth.create_user(email, password, name=name)
        
        return {
            "message": "User created successfully",
            "result": result,
            "provider": unified_auth.provider
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"User creation failed: {str(e)}"
        )


@router.get("/users/{user_id}")
async def get_external_user(
    user_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get user from external provider."""
    try:
        # Check if user has permission to read users
        if not current_user.is_superuser and str(current_user.id) != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to read user"
            )
        
        if unified_auth.provider == "cognito":
            from app.core.auth.cognito import cognito_auth
            user_info = cognito_auth.get_user_by_id(user_id)
        elif unified_auth.provider == "auth0":
            from app.core.auth.auth0 import auth0_auth
            user_info = auth0_auth.get_user_by_id(user_id)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="External user management not configured"
            )
        
        return {
            "user": user_info,
            "provider": unified_auth.provider
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get user: {str(e)}"
        )


@router.put("/users/{user_id}")
async def update_external_user(
    user_id: str,
    updates: Dict[str, Any],
    current_user: User = Depends(get_current_user)
):
    """Update user in external provider."""
    try:
        # Check if user has permission to update users
        if not current_user.is_superuser and str(current_user.id) != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to update user"
            )
        
        if unified_auth.provider == "cognito":
            from app.core.auth.cognito import cognito_auth
            result = cognito_auth.update_user(user_id, updates)
        elif unified_auth.provider == "auth0":
            from app.core.auth.auth0 import auth0_auth
            result = auth0_auth.update_user(user_id, updates)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="External user management not configured"
            )
        
        return {
            "message": "User updated successfully",
            "result": result,
            "provider": unified_auth.provider
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"User update failed: {str(e)}"
        )


@router.delete("/users/{user_id}")
async def delete_external_user(
    user_id: str,
    current_user: User = Depends(get_current_user)
):
    """Delete user from external provider."""
    try:
        # Check if user has permission to delete users
        if not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to delete users"
            )
        
        # Prevent self-deletion
        if str(current_user.id) == user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete your own account"
            )
        
        if unified_auth.provider == "cognito":
            from app.core.auth.cognito import cognito_auth
            result = cognito_auth.delete_user(user_id)
        elif unified_auth.provider == "auth0":
            from app.core.auth.auth0 import auth0_auth
            result = auth0_auth.delete_user(user_id)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="External user management not configured"
            )
        
        return {
            "message": "User deleted successfully",
            "result": result,
            "provider": unified_auth.provider
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"User deletion failed: {str(e)}"
        )


# Password Management
@router.post("/users/{user_id}/reset-password")
async def reset_external_password(
    user_id: str,
    current_user: User = Depends(get_current_user)
):
    """Reset password for external user."""
    try:
        # Check if user has permission to reset passwords
        if not current_user.is_superuser and str(current_user.id) != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to reset password"
            )
        
        if unified_auth.provider == "cognito":
            from app.core.auth.cognito import cognito_auth
            result = cognito_auth.reset_password(user_id)
        elif unified_auth.provider == "auth0":
            # Auth0 doesn't support password reset via API in the same way
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password reset not supported for Auth0 via API"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="External password management not configured"
            )
        
        return {
            "message": "Password reset initiated successfully",
            "result": result,
            "provider": unified_auth.provider
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password reset failed: {str(e)}"
        )


@router.post("/users/{user_id}/confirm-reset-password")
async def confirm_reset_external_password(
    user_id: str,
    confirmation_code: str,
    new_password: str,
    current_user: User = Depends(get_current_user)
):
    """Confirm password reset for external user."""
    try:
        # Check if user has permission to reset passwords
        if not current_user.is_superuser and str(current_user.id) != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to reset password"
            )
        
        if unified_auth.provider == "cognito":
            from app.core.auth.cognito import cognito_auth
            result = cognito_auth.confirm_reset_password(user_id, confirmation_code, new_password)
        elif unified_auth.provider == "auth0":
            # Auth0 doesn't support password reset confirmation via API
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password reset confirmation not supported for Auth0 via API"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="External password management not configured"
            )
        
        return {
            "message": "Password reset confirmed successfully",
            "result": result,
            "provider": unified_auth.provider
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password reset confirmation failed: {str(e)}"
        )


# Provider Information
@router.get("/provider/info")
async def get_provider_info():
    """Get information about the configured authentication provider."""
    return get_auth_provider_info()


@router.get("/provider/status")
async def get_provider_status():
    """Get status of the configured authentication provider."""
    try:
        info = get_auth_provider_info()
        
        # Test provider connectivity
        status_info = {
            "provider": info["provider"],
            "configured": info["configured"],
            "status": "healthy" if info["configured"] else "not_configured",
            "features": info["features"]
        }
        
        return status_info
        
    except Exception as e:
        return {
            "provider": "unknown",
            "configured": False,
            "status": "error",
            "error": str(e)
        }


# Webhook Endpoints (for Auth0)
@router.post("/webhooks/auth0")
async def auth0_webhook(
    request: Request,
    db: Session = Depends(get_db_session)
):
    """Handle Auth0 webhooks for user events."""
    try:
        # Get webhook payload
        payload = await request.json()
        
        # Validate webhook signature
        signature = request.headers.get("x-auth0-signature")
        if not signature:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing webhook signature"
            )
        
        from app.core.auth.auth0 import auth0_auth
        if not auth0_auth.validate_webhook_signature(payload, signature):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature"
            )
        
        # Process webhook based on event type
        event_type = payload.get("type")
        
        if event_type == "user.created":
            # Handle user creation
            user_info = payload.get("user", {})
            user = auth0_auth.sync_user_with_rbac(db, user_info)
            
        elif event_type == "user.updated":
            # Handle user update
            user_info = payload.get("user", {})
            user = auth0_auth.sync_user_with_rbac(db, user_info)
            
        elif event_type == "user.deleted":
            # Handle user deletion
            user_id = payload.get("user", {}).get("user_id")
            # Mark user as inactive in local system
            pass
        
        return {"message": "Webhook processed successfully"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Webhook processing failed: {str(e)}"
        ) 
"""
Authentication API Endpoints

Handles user authentication, registration, and token management.
"""

from datetime import timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from app.core.rbac import (
    get_db_session, get_rbac_auth, RBACAuth,
    get_current_user, get_current_active_user
)
from app.core.rbac.models import (
    User, UserCreate, UserResponse, LoginRequest, LoginResponse
)
from app.core.rbac.roles import RoleManager

router = APIRouter(prefix="/auth", tags=["authentication"])

security = HTTPBearer()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db_session)
):
    """
    Register a new user.
    
    Args:
        user_data: User registration data
        db: Database session
        
    Returns:
        Created user information
    """
    rbac_auth = get_rbac_auth(db)
    
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Check if email already exists
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash password
    hashed_password = rbac_auth.get_password_hash(user_data.password)
    
    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        is_active=user_data.is_active
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Assign default role (user)
    role_manager = RoleManager(db)
    default_role = role_manager.get_role_by_name("user")
    if default_role:
        role_manager.assign_role_to_user(user.id, default_role.id)
    
    return user


@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db_session)
):
    """
    Authenticate user and return access token.
    
    Args:
        login_data: Login credentials
        db: Database session
        
    Returns:
        Access token and user information
    """
    rbac_auth = get_rbac_auth(db)
    
    # Authenticate user
    user = rbac_auth.authenticate_user(login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = rbac_auth.create_access_token(
        data={"sub": user.username, "user_id": user.id},
        expires_delta=access_token_expires
    )
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=30 * 60,  # 30 minutes in seconds
        user=user
    )


@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """
    Refresh the access token for the current user.
    
    Args:
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        New access token and user information
    """
    rbac_auth = get_rbac_auth(db)
    
    # Create new access token
    access_token_expires = timedelta(minutes=30)
    access_token = rbac_auth.create_access_token(
        data={"sub": current_user.username, "user_id": current_user.id},
        expires_delta=access_token_expires
    )
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=30 * 60,  # 30 minutes in seconds
        user=current_user
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get information about the current authenticated user.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Current user information
    """
    return current_user


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_active_user)
):
    """
    Logout the current user (client-side token invalidation).
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Logout confirmation
    """
    # Note: JWT tokens are stateless, so server-side logout
    # would require a token blacklist. For now, we just return success.
    return {"message": "Successfully logged out"}


@router.post("/change-password")
async def change_password(
    current_password: str,
    new_password: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db_session)
):
    """
    Change the current user's password.
    
    Args:
        current_password: Current password
        new_password: New password
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Password change confirmation
    """
    rbac_auth = get_rbac_auth(db)
    
    # Verify current password
    if not rbac_auth.verify_password(current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Hash new password
    new_hashed_password = rbac_auth.get_password_hash(new_password)
    
    # Update password
    current_user.hashed_password = new_hashed_password
    db.commit()
    
    return {"message": "Password changed successfully"}


@router.get("/verify-token")
async def verify_token(
    current_user: User = Depends(get_current_active_user)
):
    """
    Verify if the current token is valid.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Token verification result
    """
    return {
        "valid": True,
        "user_id": current_user.id,
        "username": current_user.username,
        "is_active": current_user.is_active,
        "is_superuser": current_user.is_superuser
    } 
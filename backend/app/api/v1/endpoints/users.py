"""
User Management API Endpoints

Provides endpoints for user management with RBAC integration.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.rbac import (
    get_db_session, get_rbac_auth, RBACAuth,
    get_current_user, require_permissions, require_roles
)
from app.core.rbac.models import (
    User, UserCreate, UserUpdate, UserResponse
)
from app.core.rbac.roles import RoleManager

router = APIRouter(prefix="/users", tags=["user-management"])


@router.get("/", response_model=List[UserResponse])
@require_permissions(["user:read"])
async def get_users(
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of users to return"),
    active_only: bool = Query(True, description="Return only active users"),
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Get a list of users with pagination."""
    query = db.query(User)
    
    if active_only:
        query = query.filter(User.is_active == True)
    
    users = query.offset(skip).limit(limit).all()
    return users


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information."""
    return current_user


@router.get("/{user_id}", response_model=UserResponse)
@require_permissions(["user:read"])
async def get_user(
    user_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Get a specific user by ID."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@require_permissions(["user:create"])
async def create_user(
    user_data: UserCreate,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Create a new user."""
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
        role_manager.assign_role_to_user(user.id, default_role.id, assigned_by=current_user.id)
    
    return user


@router.put("/{user_id}", response_model=UserResponse)
@require_permissions(["user:update"])
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Update an existing user."""
    # Check if user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if username conflicts (if being updated)
    if user_data.username and user_data.username != user.username:
        existing_user = db.query(User).filter(User.username == user_data.username).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
    
    # Check if email conflicts (if being updated)
    if user_data.email and user_data.email != user.email:
        existing_email = db.query(User).filter(User.email == user_data.email).first()
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already exists"
            )
    
    # Update user fields
    update_data = user_data.dict(exclude_unset=True)
    
    # Handle password update separately
    if "password" in update_data:
        rbac_auth = get_rbac_auth(db)
        update_data["hashed_password"] = rbac_auth.get_password_hash(update_data.pop("password"))
    
    for field, value in update_data.items():
        if hasattr(user, field):
            setattr(user, field, value)
    
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permissions(["user:delete"])
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Delete a user (soft delete by setting is_active to False)."""
    # Check if user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent self-deletion
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    # Soft delete
    user.is_active = False
    db.commit()


@router.patch("/{user_id}/activate", response_model=UserResponse)
@require_permissions(["user:update"])
async def activate_user(
    user_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Activate a deactivated user."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.is_active = True
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}/deactivate", response_model=UserResponse)
@require_permissions(["user:update"])
async def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Deactivate a user."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent self-deactivation
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )
    
    user.is_active = False
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}/reset-password", response_model=UserResponse)
@require_permissions(["user:update"])
async def reset_user_password(
    user_id: int,
    new_password: str,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Reset a user's password."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Hash new password
    rbac_auth = get_rbac_auth(db)
    user.hashed_password = rbac_auth.get_password_hash(new_password)
    
    db.commit()
    db.refresh(user)
    return user


@router.get("/search", response_model=List[UserResponse])
@require_permissions(["user:read"])
async def search_users(
    q: str = Query(..., description="Search query for username, email, or full name"),
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of users to return"),
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Search users by username, email, or full name."""
    query = db.query(User).filter(
        User.is_active == True,
        (
            User.username.ilike(f"%{q}%") |
            User.email.ilike(f"%{q}%") |
            User.first_name.ilike(f"%{q}%") |
            User.last_name.ilike(f"%{q}%")
        )
    )
    
    users = query.offset(skip).limit(limit).all()
    return users


@router.get("/{user_id}/profile")
@require_permissions(["user:read"])
async def get_user_profile(
    user_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Get detailed user profile information including roles and permissions."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Get user roles
    role_manager = RoleManager(db)
    user_roles = role_manager.get_user_role_names(user_id)
    
    # Get user permissions
    from app.core.rbac.permissions import PermissionManager
    permission_manager = PermissionManager(db)
    user_permissions = permission_manager.get_user_permissions(user_id)
    
    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_active": user.is_active,
            "is_superuser": user.is_superuser,
            "created_at": user.created_at,
            "last_login": user.last_login
        },
        "roles": user_roles,
        "permissions": [p.name for p in user_permissions]
    } 
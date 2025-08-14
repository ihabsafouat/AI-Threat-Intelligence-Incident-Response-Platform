"""
RBAC Management API Endpoints

Provides endpoints for managing roles, permissions, and user-role assignments.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.rbac import (
    get_db_session, get_rbac_auth, RBACAuth,
    get_current_user, require_permissions, require_roles
)
from app.core.rbac.models import (
    User, Role, Permission, UserRole, RolePermission,
    RoleCreate, RoleUpdate, RoleResponse,
    PermissionCreate, PermissionUpdate, PermissionResponse,
    UserRoleCreate, UserRoleResponse, RolePermissionCreate, RolePermissionResponse
)
from app.core.rbac.roles import RoleManager
from app.core.rbac.permissions import PermissionManager

router = APIRouter(prefix="/rbac", tags=["rbac-management"])


# Role Management Endpoints
@router.get("/roles", response_model=List[RoleResponse])
@require_permissions(["role:read"])
async def get_all_roles(
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Get all available roles."""
    role_manager = RoleManager(db)
    return role_manager.get_all_roles()


@router.get("/roles/{role_id}", response_model=RoleResponse)
@require_permissions(["role:read"])
async def get_role(
    role_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Get a specific role by ID."""
    role_manager = RoleManager(db)
    role = role_manager.get_role_by_id(role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    return role


@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
@require_permissions(["role:create"])
async def create_role(
    role_data: RoleCreate,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Create a new role."""
    role_manager = RoleManager(db)
    
    # Check if role name already exists
    existing_role = role_manager.get_role_by_name(role_data.name)
    if existing_role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role name already exists"
        )
    
    role = role_manager.create_role(
        name=role_data.name,
        description=role_data.description
    )
    return role


@router.put("/roles/{role_id}", response_model=RoleResponse)
@require_permissions(["role:update"])
async def update_role(
    role_id: int,
    role_data: RoleUpdate,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Update an existing role."""
    role_manager = RoleManager(db)
    
    # Check if role exists
    existing_role = role_manager.get_role_by_id(role_id)
    if not existing_role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    # Check if new name conflicts with existing role
    if role_data.name and role_data.name != existing_role.name:
        name_conflict = role_manager.get_role_by_name(role_data.name)
        if name_conflict:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role name already exists"
            )
    
    updated_role = role_manager.update_role(role_id, **role_data.dict(exclude_unset=True))
    return updated_role


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permissions(["role:delete"])
async def delete_role(
    role_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Delete a role (soft delete)."""
    role_manager = RoleManager(db)
    
    # Check if role exists
    existing_role = role_manager.get_role_by_id(role_id)
    if not existing_role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    # Check if role is assigned to any users
    if role_manager.get_users_with_role(role_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete role that is assigned to users"
        )
    
    role_manager.delete_role(role_id)


# Permission Management Endpoints
@router.get("/permissions", response_model=List[PermissionResponse])
@require_permissions(["permission:read"])
async def get_all_permissions(
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Get all available permissions."""
    permission_manager = PermissionManager(db)
    return permission_manager.get_all_permissions()


@router.get("/permissions/{permission_id}", response_model=PermissionResponse)
@require_permissions(["permission:read"])
async def get_permission(
    permission_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Get a specific permission by ID."""
    permission_manager = PermissionManager(db)
    permission = permission_manager.get_permission_by_id(permission_id)
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    return permission


@router.post("/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
@require_permissions(["permission:create"])
async def create_permission(
    permission_data: PermissionCreate,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Create a new permission."""
    permission_manager = PermissionManager(db)
    
    # Check if permission name already exists
    existing_permission = permission_manager.get_permission_by_name(permission_data.name)
    if existing_permission:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission name already exists"
        )
    
    permission = permission_manager.create_permission(
        name=permission_data.name,
        description=permission_data.description,
        resource=permission_data.resource,
        action=permission_data.action
    )
    return permission


@router.put("/permissions/{permission_id}", response_model=PermissionResponse)
@require_permissions(["permission:update"])
async def update_permission(
    permission_id: int,
    permission_data: PermissionUpdate,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Update an existing permission."""
    permission_manager = PermissionManager(db)
    
    # Check if permission exists
    existing_permission = permission_manager.get_permission_by_id(permission_id)
    if not existing_permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    
    # Check if new name conflicts with existing permission
    if permission_data.name and permission_data.name != existing_permission.name:
        name_conflict = permission_manager.get_permission_by_name(permission_data.name)
        if name_conflict:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Permission name already exists"
            )
    
    updated_permission = permission_manager.update_permission(
        permission_id, **permission_data.dict(exclude_unset=True)
    )
    return updated_permission


@router.delete("/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permissions(["permission:delete"])
async def delete_permission(
    permission_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Delete a permission (soft delete)."""
    permission_manager = PermissionManager(db)
    
    # Check if permission exists
    existing_permission = permission_manager.get_permission_by_id(permission_id)
    if not existing_permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    
    # Check if permission is assigned to any roles
    if permission_manager.get_roles_with_permission(permission_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete permission that is assigned to roles"
        )
    
    permission_manager.delete_permission(permission_id)


# User-Role Assignment Endpoints
@router.get("/users/{user_id}/roles", response_model=List[UserRoleResponse])
@require_permissions(["user:read"])
async def get_user_roles(
    user_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Get all roles assigned to a specific user."""
    role_manager = RoleManager(db)
    user_roles = role_manager.get_user_roles(user_id)
    return user_roles


@router.post("/users/{user_id}/roles", response_model=UserRoleResponse, status_code=status.HTTP_201_CREATED)
@require_permissions(["user:assign_roles"])
async def assign_role_to_user(
    user_id: int,
    role_assignment: UserRoleCreate,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Assign a role to a user."""
    role_manager = RoleManager(db)
    
    # Check if user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if role exists
    role = role_manager.get_role_by_id(role_assignment.role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    # Check if role is already assigned
    existing_assignment = role_manager.get_user_role_assignment(user_id, role_assignment.role_id)
    if existing_assignment:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role is already assigned to this user"
        )
    
    user_role = role_manager.assign_role_to_user(
        user_id=user_id,
        role_id=role_assignment.role_id,
        assigned_by=current_user.id,
        expires_at=role_assignment.expires_at
    )
    return user_role


@router.delete("/users/{user_id}/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permissions(["user:assign_roles"])
async def remove_role_from_user(
    user_id: int,
    role_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Remove a role from a user."""
    role_manager = RoleManager(db)
    
    # Check if assignment exists
    assignment = role_manager.get_user_role_assignment(user_id, role_id)
    if not assignment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role assignment not found"
        )
    
    role_manager.remove_role_from_user(user_id, role_id)


# Role-Permission Assignment Endpoints
@router.get("/roles/{role_id}/permissions", response_model=List[RolePermissionResponse])
@require_permissions(["role:read"])
async def get_role_permissions(
    role_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Get all permissions assigned to a specific role."""
    permission_manager = PermissionManager(db)
    role_permissions = permission_manager.get_role_permissions(role_id)
    return role_permissions


@router.post("/roles/{role_id}/permissions", response_model=RolePermissionResponse, status_code=status.HTTP_201_CREATED)
@require_permissions(["role:assign_permissions"])
async def assign_permission_to_role(
    role_id: int,
    permission_assignment: RolePermissionCreate,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Assign a permission to a role."""
    permission_manager = PermissionManager(db)
    role_manager = RoleManager(db)
    
    # Check if role exists
    role = role_manager.get_role_by_id(role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    
    # Check if permission exists
    permission = permission_manager.get_permission_by_id(permission_assignment.permission_id)
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    
    # Check if permission is already assigned
    existing_assignment = permission_manager.get_role_permission_assignment(
        role_id, permission_assignment.permission_id
    )
    if existing_assignment:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission is already assigned to this role"
        )
    
    role_permission = permission_manager.assign_permission_to_role(
        role_id=role_id,
        permission_id=permission_assignment.permission_id,
        granted_by=current_user.id,
        expires_at=permission_assignment.expires_at
    )
    return role_permission


@router.delete("/roles/{role_id}/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_permissions(["role:assign_permissions"])
async def remove_permission_from_role(
    role_id: int,
    permission_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Remove a permission from a role."""
    permission_manager = PermissionManager(db)
    
    # Check if assignment exists
    assignment = permission_manager.get_role_permission_assignment(role_id, permission_id)
    if not assignment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission assignment not found"
        )
    
    permission_manager.remove_permission_from_role(role_id, permission_id)


# Utility Endpoints
@router.get("/users/{user_id}/permissions")
@require_permissions(["user:read"])
async def get_user_permissions(
    user_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Get all permissions for a specific user (including inherited from roles)."""
    permission_manager = PermissionManager(db)
    permissions = permission_manager.get_user_permissions(user_id)
    return {"user_id": user_id, "permissions": [p.name for p in permissions]}


@router.get("/check-permission")
async def check_user_permission(
    permission: str,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Check if the current user has a specific permission."""
    permission_manager = PermissionManager(db)
    has_permission = permission_manager.user_has_permission(current_user.id, permission)
    return {
        "user_id": current_user.id,
        "permission": permission,
        "has_permission": has_permission
    }


@router.get("/check-role")
async def check_user_role(
    role: str,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Check if the current user has a specific role."""
    role_manager = RoleManager(db)
    has_role = role_manager.user_has_role(current_user.id, role)
    return {
        "user_id": current_user.id,
        "role": role,
        "has_role": has_role
    } 
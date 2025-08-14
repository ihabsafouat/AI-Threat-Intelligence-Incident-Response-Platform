"""
Role-Based Access Control (RBAC) Module

This module provides comprehensive RBAC functionality for the Threat Intelligence Platform.
"""

from .models import User, Role, Permission, UserRole, RolePermission
from .auth import RBACAuth, get_current_user, require_permissions, require_roles
from .permissions import PermissionManager, PermissionEnum
from .roles import RoleManager, RoleEnum
from .middleware import RBACMiddleware
from .database import RBACDatabase

__all__ = [
    'User',
    'Role', 
    'Permission',
    'UserRole',
    'RolePermission',
    'RBACAuth',
    'get_current_user',
    'require_permissions',
    'require_roles',
    'PermissionManager',
    'PermissionEnum',
    'RoleManager',
    'RoleEnum',
    'RBACMiddleware',
    'RBACDatabase'
] 
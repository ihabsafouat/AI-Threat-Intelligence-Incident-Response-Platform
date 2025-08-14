"""
Permission Management System

Defines and manages permissions for the RBAC system.
"""

from enum import Enum
from typing import List, Dict, Optional, Set
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .models import Permission, Role, User


class PermissionEnum(Enum):
    """Predefined permissions for the threat intelligence platform."""
    
    # User Management
    USER_READ = "user:read"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_ASSIGN_ROLES = "user:assign_roles"
    
    # Role Management
    ROLE_READ = "role:read"
    ROLE_CREATE = "role:create"
    ROLE_UPDATE = "role:update"
    ROLE_DELETE = "role:delete"
    ROLE_ASSIGN_PERMISSIONS = "role:assign_permissions"
    
    # Permission Management
    PERMISSION_READ = "permission:read"
    PERMISSION_CREATE = "permission:create"
    PERMISSION_UPDATE = "permission:update"
    PERMISSION_DELETE = "permission:delete"
    
    # Threat Intelligence
    THREAT_READ = "threat:read"
    THREAT_CREATE = "threat:create"
    THREAT_UPDATE = "threat:update"
    THREAT_DELETE = "threat:delete"
    THREAT_ANALYZE = "threat:analyze"
    THREAT_EXPORT = "threat:export"
    
    # Threat Sources
    SOURCE_READ = "source:read"
    SOURCE_CREATE = "source:create"
    SOURCE_UPDATE = "source:update"
    SOURCE_DELETE = "source:delete"
    SOURCE_CONFIGURE = "source:configure"
    
    # Reports
    REPORT_READ = "report:read"
    REPORT_CREATE = "report:create"
    REPORT_UPDATE = "report:update"
    REPORT_DELETE = "report:delete"
    REPORT_EXPORT = "report:export"
    REPORT_SCHEDULE = "report:schedule"
    
    # Analytics
    ANALYTICS_READ = "analytics:read"
    ANALYTICS_CREATE = "analytics:create"
    ANALYTICS_UPDATE = "analytics:update"
    ANALYTICS_DELETE = "analytics:delete"
    ANALYTICS_EXPORT = "analytics:export"
    
    # System Administration
    SYSTEM_CONFIG = "system:config"
    SYSTEM_LOGS = "system:logs"
    SYSTEM_BACKUP = "system:backup"
    SYSTEM_RESTORE = "system:restore"
    SYSTEM_MONITOR = "system:monitor"
    
    # API Management
    API_READ = "api:read"
    API_CREATE = "api:create"
    API_UPDATE = "api:update"
    API_DELETE = "api:delete"
    API_RATE_LIMIT = "api:rate_limit"
    
    # Dashboard
    DASHBOARD_READ = "dashboard:read"
    DASHBOARD_CREATE = "dashboard:create"
    DASHBOARD_UPDATE = "dashboard:update"
    DASHBOARD_DELETE = "dashboard:delete"
    DASHBOARD_SHARE = "dashboard:share"


class PermissionManager:
    """Manages permissions in the RBAC system."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_all_permissions(self) -> List[Permission]:
        """Get all permissions from the database."""
        return self.db.query(Permission).filter(Permission.is_active == True).all()
    
    def get_permission_by_name(self, name: str) -> Optional[Permission]:
        """Get a permission by its name."""
        return self.db.query(Permission).filter(
            Permission.name == name,
            Permission.is_active == True
        ).first()
    
    def get_permissions_by_resource(self, resource: str) -> List[Permission]:
        """Get all permissions for a specific resource."""
        return self.db.query(Permission).filter(
            Permission.resource == resource,
            Permission.is_active == True
        ).all()
    
    def get_permissions_by_action(self, action: str) -> List[Permission]:
        """Get all permissions for a specific action."""
        return self.db.query(Permission).filter(
            Permission.action == action,
            Permission.is_active == True
        ).all()
    
    def create_permission(self, name: str, description: str, resource: str, action: str) -> Permission:
        """Create a new permission."""
        permission = Permission(
            name=name,
            description=description,
            resource=resource,
            action=action
        )
        self.db.add(permission)
        self.db.commit()
        self.db.refresh(permission)
        return permission
    
    def update_permission(self, permission_id: int, **kwargs) -> Optional[Permission]:
        """Update an existing permission."""
        permission = self.db.query(Permission).filter(Permission.id == permission_id).first()
        if not permission:
            return None
        
        for key, value in kwargs.items():
            if hasattr(permission, key):
                setattr(permission, key, value)
        
        permission.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(permission)
        return permission
    
    def delete_permission(self, permission_id: int) -> bool:
        """Soft delete a permission by setting is_active to False."""
        permission = self.db.query(Permission).filter(Permission.id == permission_id).first()
        if not permission:
            return False
        
        permission.is_active = False
        permission.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        return True
    
    def get_user_permissions(self, user_id: int) -> Set[str]:
        """Get all permissions for a user (including superuser permissions)."""
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return set()
        
        # Superusers have all permissions
        if user.is_superuser:
            return {perm.name for perm in self.get_all_permissions()}
        
        # Get permissions from user's roles
        permissions = set()
        for role in user.roles:
            if role.is_active:
                for permission in role.permissions:
                    if permission.is_active:
                        permissions.add(permission.name)
        
        return permissions
    
    def get_user_permissions_by_resource(self, user_id: int, resource: str) -> Set[str]:
        """Get user permissions for a specific resource."""
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return set()
        
        # Superusers have all permissions
        if user.is_superuser:
            return {perm.name for perm in self.get_permissions_by_resource(resource)}
        
        # Get permissions from user's roles for the specific resource
        permissions = set()
        for role in user.roles:
            if role.is_active:
                for permission in role.permissions:
                    if permission.is_active and permission.resource == resource:
                        permissions.add(permission.name)
        
        return permissions
    
    def check_permission(self, user_id: int, permission_name: str) -> bool:
        """Check if a user has a specific permission."""
        user_permissions = self.get_user_permissions(user_id)
        return permission_name in user_permissions
    
    def check_permissions(self, user_id: int, permission_names: List[str], require_all: bool = True) -> bool:
        """Check if a user has specific permissions."""
        user_permissions = self.get_user_permissions(user_id)
        
        if require_all:
            return all(perm in user_permissions for perm in permission_names)
        else:
            return any(perm in user_permissions for perm in permission_names)
    
    def check_resource_permission(self, user_id: int, resource: str, action: str) -> bool:
        """Check if a user has permission for a specific resource and action."""
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        
        # Superusers have all permissions
        if user.is_superuser:
            return True
        
        # Check if user has the specific resource:action permission
        permission_name = f"{resource}:{action}"
        return self.check_permission(user_id, permission_name)
    
    def initialize_default_permissions(self) -> List[Permission]:
        """Initialize default permissions in the database."""
        default_permissions = [
            # User Management
            ("user:read", "Read user information", "user", "read"),
            ("user:create", "Create new users", "user", "create"),
            ("user:update", "Update user information", "user", "update"),
            ("user:delete", "Delete users", "user", "delete"),
            ("user:assign_roles", "Assign roles to users", "user", "assign_roles"),
            
            # Role Management
            ("role:read", "Read role information", "role", "read"),
            ("role:create", "Create new roles", "role", "create"),
            ("role:update", "Update role information", "role", "update"),
            ("role:delete", "Delete roles", "role", "delete"),
            ("role:assign_permissions", "Assign permissions to roles", "role", "assign_permissions"),
            
            # Permission Management
            ("permission:read", "Read permission information", "permission", "read"),
            ("permission:create", "Create new permissions", "permission", "create"),
            ("permission:update", "Update permission information", "permission", "update"),
            ("permission:delete", "Delete permissions", "permission", "delete"),
            
            # Threat Intelligence
            ("threat:read", "Read threat information", "threat", "read"),
            ("threat:create", "Create new threats", "threat", "create"),
            ("threat:update", "Update threat information", "threat", "update"),
            ("threat:delete", "Delete threats", "threat", "delete"),
            ("threat:analyze", "Analyze threats", "threat", "analyze"),
            ("threat:export", "Export threat data", "threat", "export"),
            
            # Threat Sources
            ("source:read", "Read source information", "source", "read"),
            ("source:create", "Create new sources", "source", "create"),
            ("source:update", "Update source information", "source", "update"),
            ("source:delete", "Delete sources", "source", "delete"),
            ("source:configure", "Configure sources", "source", "configure"),
            
            # Reports
            ("report:read", "Read reports", "report", "read"),
            ("report:create", "Create new reports", "report", "create"),
            ("report:update", "Update reports", "report", "update"),
            ("report:delete", "Delete reports", "report", "delete"),
            ("report:export", "Export reports", "report", "export"),
            ("report:schedule", "Schedule reports", "report", "schedule"),
            
            # Analytics
            ("analytics:read", "Read analytics", "analytics", "read"),
            ("analytics:create", "Create new analytics", "analytics", "create"),
            ("analytics:update", "Update analytics", "analytics", "update"),
            ("analytics:delete", "Delete analytics", "analytics", "delete"),
            ("analytics:export", "Export analytics", "analytics", "export"),
            
            # System Administration
            ("system:config", "Configure system settings", "system", "config"),
            ("system:logs", "Access system logs", "system", "logs"),
            ("system:backup", "Create system backups", "system", "backup"),
            ("system:restore", "Restore system from backup", "system", "restore"),
            ("system:monitor", "Monitor system health", "system", "monitor"),
            
            # API Management
            ("api:read", "Read API information", "api", "read"),
            ("api:create", "Create new APIs", "api", "create"),
            ("api:update", "Update API information", "api", "update"),
            ("api:delete", "Delete APIs", "api", "delete"),
            ("api:rate_limit", "Manage API rate limits", "api", "rate_limit"),
            
            # Dashboard
            ("dashboard:read", "Read dashboards", "dashboard", "read"),
            ("dashboard:create", "Create new dashboards", "dashboard", "create"),
            ("dashboard:update", "Update dashboards", "dashboard", "update"),
            ("dashboard:delete", "Delete dashboards", "dashboard", "delete"),
            ("dashboard:share", "Share dashboards", "dashboard", "share"),
        ]
        
        created_permissions = []
        for name, description, resource, action in default_permissions:
            # Check if permission already exists
            existing = self.get_permission_by_name(name)
            if not existing:
                permission = self.create_permission(name, description, resource, action)
                created_permissions.append(permission)
        
        return created_permissions
    
    def get_permission_statistics(self) -> Dict[str, int]:
        """Get statistics about permissions."""
        total_permissions = self.db.query(Permission).count()
        active_permissions = self.db.query(Permission).filter(Permission.is_active == True).count()
        inactive_permissions = total_permissions - active_permissions
        
        # Count permissions by resource
        resource_counts = {}
        permissions = self.get_all_permissions()
        for permission in permissions:
            resource = permission.resource
            resource_counts[resource] = resource_counts.get(resource, 0) + 1
        
        return {
            "total_permissions": total_permissions,
            "active_permissions": active_permissions,
            "inactive_permissions": inactive_permissions,
            "permissions_by_resource": resource_counts
        } 
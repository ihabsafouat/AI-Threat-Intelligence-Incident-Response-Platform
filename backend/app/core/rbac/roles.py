"""
Role Management System

Defines and manages roles for the RBAC system.
"""

from enum import Enum
from typing import List, Dict, Optional, Set
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .models import Role, User, Permission
from .permissions import PermissionManager


class RoleEnum(Enum):
    """Predefined roles for the threat intelligence platform."""
    
    # System Roles
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    USER = "user"
    
    # Security Roles
    SECURITY_ANALYST = "security_analyst"
    THREAT_HUNTER = "threat_hunter"
    INCIDENT_RESPONDER = "incident_responder"
    SOC_ANALYST = "soc_analyst"
    
    # Management Roles
    SECURITY_MANAGER = "security_manager"
    IT_MANAGER = "it_manager"
    COMPLIANCE_OFFICER = "compliance_officer"
    
    # Technical Roles
    SYSTEM_ADMIN = "system_admin"
    DEVELOPER = "developer"
    DATA_ANALYST = "data_analyst"
    RESEARCHER = "researcher"
    
    # Read-only Roles
    VIEWER = "viewer"
    REPORTER = "reporter"
    AUDITOR = "auditor"


class RoleManager:
    """Manages roles in the RBAC system."""
    
    def __init__(self, db: Session):
        self.db = db
        self.permission_manager = PermissionManager(db)
    
    def get_all_roles(self) -> List[Role]:
        """Get all roles from the database."""
        return self.db.query(Role).filter(Role.is_active == True).all()
    
    def get_role_by_name(self, name: str) -> Optional[Role]:
        """Get a role by its name."""
        return self.db.query(Role).filter(
            Role.name == name,
            Role.is_active == True
        ).first()
    
    def get_role_by_id(self, role_id: int) -> Optional[Role]:
        """Get a role by its ID."""
        return self.db.query(Role).filter(Role.id == role_id).first()
    
    def create_role(self, name: str, description: str = None) -> Role:
        """Create a new role."""
        role = Role(
            name=name,
            description=description
        )
        self.db.add(role)
        self.db.commit()
        self.db.refresh(role)
        return role
    
    def update_role(self, role_id: int, **kwargs) -> Optional[Role]:
        """Update an existing role."""
        role = self.get_role_by_id(role_id)
        if not role:
            return None
        
        for key, value in kwargs.items():
            if hasattr(role, key):
                setattr(role, key, value)
        
        role.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(role)
        return role
    
    def delete_role(self, role_id: int) -> bool:
        """Soft delete a role by setting is_active to False."""
        role = self.get_role_by_id(role_id)
        if not role:
            return False
        
        role.is_active = False
        role.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        return True
    
    def assign_permission_to_role(self, role_id: int, permission_id: int, granted_by: int = None) -> bool:
        """Assign a permission to a role."""
        from .models import RolePermission
        
        # Check if assignment already exists
        existing = self.db.query(RolePermission).filter(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id,
            RolePermission.is_active == True
        ).first()
        
        if existing:
            return True  # Already assigned
        
        role_permission = RolePermission(
            role_id=role_id,
            permission_id=permission_id,
            granted_by=granted_by
        )
        self.db.add(role_permission)
        self.db.commit()
        return True
    
    def remove_permission_from_role(self, role_id: int, permission_id: int) -> bool:
        """Remove a permission from a role."""
        from .models import RolePermission
        
        role_permission = self.db.query(RolePermission).filter(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id,
            RolePermission.is_active == True
        ).first()
        
        if not role_permission:
            return False
        
        role_permission.is_active = False
        self.db.commit()
        return True
    
    def get_role_permissions(self, role_id: int) -> List[Permission]:
        """Get all permissions for a role."""
        role = self.get_role_by_id(role_id)
        if not role:
            return []
        
        return [perm for perm in role.permissions if perm.is_active]
    
    def assign_role_to_user(self, user_id: int, role_id: int, assigned_by: int = None) -> bool:
        """Assign a role to a user."""
        from .models import UserRole
        
        # Check if assignment already exists
        existing = self.db.query(UserRole).filter(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id,
            UserRole.is_active == True
        ).first()
        
        if existing:
            return True  # Already assigned
        
        user_role = UserRole(
            user_id=user_id,
            role_id=role_id,
            assigned_by=assigned_by
        )
        self.db.add(user_role)
        self.db.commit()
        return True
    
    def remove_role_from_user(self, user_id: int, role_id: int) -> bool:
        """Remove a role from a user."""
        from .models import UserRole
        
        user_role = self.db.query(UserRole).filter(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id,
            UserRole.is_active == True
        ).first()
        
        if not user_role:
            return False
        
        user_role.is_active = False
        self.db.commit()
        return True
    
    def get_user_roles(self, user_id: int) -> List[Role]:
        """Get all roles for a user."""
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return []
        
        return [role for role in user.roles if role.is_active]
    
    def get_user_role_names(self, user_id: int) -> Set[str]:
        """Get role names for a user."""
        roles = self.get_user_roles(user_id)
        return {role.name for role in roles}
    
    def check_user_role(self, user_id: int, role_name: str) -> bool:
        """Check if a user has a specific role."""
        user_roles = self.get_user_role_names(user_id)
        return role_name in user_roles
    
    def check_user_roles(self, user_id: int, role_names: List[str], require_all: bool = True) -> bool:
        """Check if a user has specific roles."""
        user_roles = self.get_user_role_names(user_id)
        
        if require_all:
            return all(role in user_roles for role in role_names)
        else:
            return any(role in user_roles for role in role_names)
    
    def initialize_default_roles(self) -> List[Role]:
        """Initialize default roles in the database."""
        default_roles = [
            # System Roles
            ("super_admin", "Super Administrator with full system access"),
            ("admin", "Administrator with system management capabilities"),
            ("user", "Standard user with basic access"),
            
            # Security Roles
            ("security_analyst", "Security analyst with threat analysis capabilities"),
            ("threat_hunter", "Threat hunter with advanced threat detection skills"),
            ("incident_responder", "Incident responder with incident management access"),
            ("soc_analyst", "SOC analyst with security operations center access"),
            
            # Management Roles
            ("security_manager", "Security manager with oversight capabilities"),
            ("it_manager", "IT manager with infrastructure management access"),
            ("compliance_officer", "Compliance officer with regulatory oversight"),
            
            # Technical Roles
            ("system_admin", "System administrator with technical management access"),
            ("developer", "Developer with application development access"),
            ("data_analyst", "Data analyst with analytics and reporting access"),
            ("researcher", "Researcher with threat intelligence research access"),
            
            # Read-only Roles
            ("viewer", "Viewer with read-only access to basic information"),
            ("reporter", "Reporter with access to generate and view reports"),
            ("auditor", "Auditor with access to audit logs and compliance data"),
        ]
        
        created_roles = []
        for name, description in default_roles:
            # Check if role already exists
            existing = self.get_role_by_name(name)
            if not existing:
                role = self.create_role(name, description)
                created_roles.append(role)
        
        return created_roles
    
    def assign_default_permissions_to_roles(self) -> Dict[str, List[str]]:
        """Assign default permissions to roles."""
        role_permissions = {
            # Super Admin - All permissions
            "super_admin": [perm.value for perm in self.permission_manager.get_all_permissions()],
            
            # Admin - Most permissions except super admin specific ones
            "admin": [
                "user:read", "user:create", "user:update", "user:delete", "user:assign_roles",
                "role:read", "role:create", "role:update", "role:delete", "role:assign_permissions",
                "permission:read", "permission:create", "permission:update", "permission:delete",
                "threat:read", "threat:create", "threat:update", "threat:delete", "threat:analyze", "threat:export",
                "source:read", "source:create", "source:update", "source:delete", "source:configure",
                "report:read", "report:create", "report:update", "report:delete", "report:export", "report:schedule",
                "analytics:read", "analytics:create", "analytics:update", "analytics:delete", "analytics:export",
                "system:config", "system:logs", "system:backup", "system:restore", "system:monitor",
                "api:read", "api:create", "api:update", "api:delete", "api:rate_limit",
                "dashboard:read", "dashboard:create", "dashboard:update", "dashboard:delete", "dashboard:share"
            ],
            
            # Security Analyst
            "security_analyst": [
                "threat:read", "threat:create", "threat:update", "threat:analyze", "threat:export",
                "source:read", "source:configure",
                "report:read", "report:create", "report:update", "report:export",
                "analytics:read", "analytics:create", "analytics:update", "analytics:export",
                "dashboard:read", "dashboard:create", "dashboard:update", "dashboard:share"
            ],
            
            # Threat Hunter
            "threat_hunter": [
                "threat:read", "threat:create", "threat:update", "threat:analyze", "threat:export",
                "source:read", "source:configure",
                "report:read", "report:create", "report:export",
                "analytics:read", "analytics:create", "analytics:export",
                "dashboard:read", "dashboard:create", "dashboard:update"
            ],
            
            # Incident Responder
            "incident_responder": [
                "threat:read", "threat:create", "threat:update", "threat:analyze",
                "report:read", "report:create", "report:update",
                "analytics:read", "analytics:create",
                "dashboard:read", "dashboard:create"
            ],
            
            # SOC Analyst
            "soc_analyst": [
                "threat:read", "threat:create", "threat:update", "threat:analyze",
                "source:read", "source:configure",
                "report:read", "report:create", "report:update",
                "analytics:read", "analytics:create",
                "dashboard:read", "dashboard:create"
            ],
            
            # Security Manager
            "security_manager": [
                "user:read", "user:create", "user:update", "user:assign_roles",
                "threat:read", "threat:create", "threat:update", "threat:analyze", "threat:export",
                "source:read", "source:create", "source:update", "source:configure",
                "report:read", "report:create", "report:update", "report:export", "report:schedule",
                "analytics:read", "analytics:create", "analytics:update", "analytics:export",
                "dashboard:read", "dashboard:create", "dashboard:update", "dashboard:share"
            ],
            
            # IT Manager
            "it_manager": [
                "user:read", "user:create", "user:update",
                "system:config", "system:logs", "system:monitor",
                "api:read", "api:create", "api:update",
                "dashboard:read", "dashboard:create", "dashboard:update"
            ],
            
            # Compliance Officer
            "compliance_officer": [
                "user:read",
                "report:read", "report:create", "report:export", "report:schedule",
                "analytics:read", "analytics:export",
                "system:logs",
                "dashboard:read", "dashboard:create"
            ],
            
            # System Admin
            "system_admin": [
                "system:config", "system:logs", "system:backup", "system:restore", "system:monitor",
                "api:read", "api:create", "api:update", "api:delete", "api:rate_limit",
                "dashboard:read", "dashboard:create", "dashboard:update"
            ],
            
            # Developer
            "developer": [
                "api:read", "api:create", "api:update", "api:delete",
                "dashboard:read", "dashboard:create", "dashboard:update"
            ],
            
            # Data Analyst
            "data_analyst": [
                "threat:read", "threat:export",
                "report:read", "report:create", "report:update", "report:export",
                "analytics:read", "analytics:create", "analytics:update", "analytics:export",
                "dashboard:read", "dashboard:create", "dashboard:update"
            ],
            
            # Researcher
            "researcher": [
                "threat:read", "threat:create", "threat:update", "threat:analyze", "threat:export",
                "source:read", "source:configure",
                "report:read", "report:create", "report:export",
                "analytics:read", "analytics:create", "analytics:export",
                "dashboard:read", "dashboard:create"
            ],
            
            # Viewer
            "viewer": [
                "threat:read",
                "report:read",
                "analytics:read",
                "dashboard:read"
            ],
            
            # Reporter
            "reporter": [
                "threat:read",
                "report:read", "report:create", "report:export",
                "analytics:read",
                "dashboard:read", "dashboard:create"
            ],
            
            # Auditor
            "auditor": [
                "user:read",
                "threat:read",
                "report:read", "report:export",
                "analytics:read", "analytics:export",
                "system:logs",
                "dashboard:read"
            ],
            
            # Standard User
            "user": [
                "threat:read",
                "report:read",
                "dashboard:read"
            ]
        }
        
        assigned_permissions = {}
        
        for role_name, permission_names in role_permissions.items():
            role = self.get_role_by_name(role_name)
            if not role:
                continue
            
            assigned_permissions[role_name] = []
            
            for permission_name in permission_names:
                permission = self.permission_manager.get_permission_by_name(permission_name)
                if permission:
                    success = self.assign_permission_to_role(role.id, permission.id)
                    if success:
                        assigned_permissions[role_name].append(permission_name)
        
        return assigned_permissions
    
    def get_role_statistics(self) -> Dict[str, int]:
        """Get statistics about roles."""
        total_roles = self.db.query(Role).count()
        active_roles = self.db.query(Role).filter(Role.is_active == True).count()
        inactive_roles = total_roles - active_roles
        
        # Count users per role
        role_user_counts = {}
        roles = self.get_all_roles()
        for role in roles:
            role_user_counts[role.name] = len(role.users)
        
        return {
            "total_roles": total_roles,
            "active_roles": active_roles,
            "inactive_roles": inactive_roles,
            "users_per_role": role_user_counts
        } 
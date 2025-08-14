"""
RBAC Database Models

Defines the database models for Role-Based Access Control.
"""

from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Table, Text
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, EmailStr, Field

Base = declarative_base()

# Association tables for many-to-many relationships
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('assigned_at', DateTime, default=datetime.now(timezone.utc)),
    Column('assigned_by', Integer, ForeignKey('users.id'))
)

role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True),
    Column('granted_at', DateTime, default=datetime.now(timezone.utc)),
    Column('granted_by', Integer, ForeignKey('users.id'))
)


class User(Base):
    """User model for authentication and authorization."""
    
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    first_name = Column(String(50))
    last_name = Column(String(50))
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    last_login = Column(DateTime)
    
    # Relationships
    roles = relationship('Role', secondary=user_roles, back_populates='users')
    assigned_roles = relationship('UserRole', back_populates='user')
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"


class Role(Base):
    """Role model for grouping permissions."""
    
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, index=True, nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # Relationships
    users = relationship('User', secondary=user_roles, back_populates='roles')
    permissions = relationship('Permission', secondary=role_permissions, back_populates='roles')
    role_permissions = relationship('RolePermission', back_populates='role')
    
    def __repr__(self):
        return f"<Role(id={self.id}, name='{self.name}')>"


class Permission(Base):
    """Permission model for defining access rights."""
    
    __tablename__ = 'permissions'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(Text)
    resource = Column(String(50), nullable=False)  # e.g., 'threats', 'users', 'reports'
    action = Column(String(50), nullable=False)    # e.g., 'read', 'write', 'delete'
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # Relationships
    roles = relationship('Role', secondary=role_permissions, back_populates='permissions')
    role_permissions = relationship('RolePermission', back_populates='permission')
    
    def __repr__(self):
        return f"<Permission(id={self.id}, name='{self.name}', resource='{self.resource}', action='{self.action}')>"


class UserRole(Base):
    """Association model for user-role relationships with additional metadata."""
    
    __tablename__ = 'user_roles'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    assigned_at = Column(DateTime, default=datetime.now(timezone.utc))
    assigned_by = Column(Integer, ForeignKey('users.id'))
    expires_at = Column(DateTime)  # Optional role expiration
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship('User', back_populates='assigned_roles')
    role = relationship('Role')
    assigned_by_user = relationship('User', foreign_keys=[assigned_by])
    
    def __repr__(self):
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id})>"


class RolePermission(Base):
    """Association model for role-permission relationships with additional metadata."""
    
    __tablename__ = 'role_permissions'
    
    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    permission_id = Column(Integer, ForeignKey('permissions.id'), nullable=False)
    granted_at = Column(DateTime, default=datetime.now(timezone.utc))
    granted_by = Column(Integer, ForeignKey('users.id'))
    expires_at = Column(DateTime)  # Optional permission expiration
    is_active = Column(Boolean, default=True)
    
    # Relationships
    role = relationship('Role', back_populates='role_permissions')
    permission = relationship('Permission', back_populates='role_permissions')
    granted_by_user = relationship('User', foreign_keys=[granted_by])
    
    def __repr__(self):
        return f"<RolePermission(role_id={self.role_id}, permission_id={self.permission_id})>"


# Pydantic models for API requests/responses
class UserBase(BaseModel):
    """Base user model for API operations."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    is_active: bool = True


class UserCreate(UserBase):
    """Model for creating a new user."""
    password: str = Field(..., min_length=8)


class UserUpdate(BaseModel):
    """Model for updating user information."""
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    is_active: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=8)


class UserResponse(UserBase):
    """Model for user API responses."""
    id: int
    is_superuser: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class RoleBase(BaseModel):
    """Base role model for API operations."""
    name: str = Field(..., min_length=2, max_length=50)
    description: Optional[str] = None
    is_active: bool = True


class RoleCreate(RoleBase):
    """Model for creating a new role."""
    pass


class RoleUpdate(BaseModel):
    """Model for updating role information."""
    name: Optional[str] = Field(None, min_length=2, max_length=50)
    description: Optional[str] = None
    is_active: Optional[bool] = None


class RoleResponse(RoleBase):
    """Model for role API responses."""
    id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class PermissionBase(BaseModel):
    """Base permission model for API operations."""
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None
    resource: str = Field(..., min_length=1, max_length=50)
    action: str = Field(..., min_length=1, max_length=50)
    is_active: bool = True


class PermissionCreate(PermissionBase):
    """Model for creating a new permission."""
    pass


class PermissionUpdate(BaseModel):
    """Model for updating permission information."""
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    resource: Optional[str] = Field(None, min_length=1, max_length=50)
    action: Optional[str] = Field(None, min_length=1, max_length=50)
    is_active: Optional[bool] = None


class PermissionResponse(PermissionBase):
    """Model for permission API responses."""
    id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class UserRoleCreate(BaseModel):
    """Model for assigning a role to a user."""
    user_id: int
    role_id: int
    expires_at: Optional[datetime] = None


class RolePermissionCreate(BaseModel):
    """Model for granting a permission to a role."""
    role_id: int
    permission_id: int
    expires_at: Optional[datetime] = None


class UserWithRoles(UserResponse):
    """Model for user with roles information."""
    roles: List[RoleResponse] = []
    
    class Config:
        from_attributes = True


class RoleWithPermissions(RoleResponse):
    """Model for role with permissions information."""
    permissions: List[PermissionResponse] = []
    
    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    """Model for user login requests."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Model for login responses."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenData(BaseModel):
    """Model for JWT token data."""
    username: Optional[str] = None
    user_id: Optional[int] = None
    permissions: List[str] = []
    roles: List[str] = [] 
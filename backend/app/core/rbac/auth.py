"""
Authentication and Authorization System

Handles user authentication, JWT token management, and permission checking.
"""

import os
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Union
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from functools import wraps

from .models import User, TokenData
from .permissions import PermissionManager
from .roles import RoleManager

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer token
security = HTTPBearer()


class RBACAuth:
    """RBAC Authentication and Authorization handler."""
    
    def __init__(self, db: Session):
        self.db = db
        self.permission_manager = PermissionManager(db)
        self.role_manager = RoleManager(db)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Hash a password."""
        return pwd_context.hash(password)
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user with username and password."""
        user = self.db.query(User).filter(User.username == username).first()
        if not user:
            return None
        if not self.verify_password(password, user.hashed_password):
            return None
        if not user.is_active:
            return None
        return user
    
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[TokenData]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            user_id: int = payload.get("user_id")
            
            if username is None or user_id is None:
                return None
            
            # Get user permissions and roles
            permissions = list(self.permission_manager.get_user_permissions(user_id))
            roles = list(self.role_manager.get_user_role_names(user_id))
            
            token_data = TokenData(
                username=username,
                user_id=user_id,
                permissions=permissions,
                roles=roles
            )
            return token_data
            
        except JWTError:
            return None
    
    def get_current_user(self, token: str = Depends(security)) -> User:
        """Get the current authenticated user."""
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        try:
            token_data = self.verify_token(token.credentials)
            if token_data is None:
                raise credentials_exception
            
            user = self.db.query(User).filter(User.id == token_data.user_id).first()
            if user is None:
                raise credentials_exception
            
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Inactive user"
                )
            
            # Update last login
            user.last_login = datetime.now(timezone.utc)
            self.db.commit()
            
            return user
            
        except JWTError:
            raise credentials_exception
    
    def get_current_active_user(self, current_user: User = Depends(get_current_user)) -> User:
        """Get the current active user."""
        if not current_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )
        return current_user
    
    def require_permissions(self, permissions: Union[str, List[str]], require_all: bool = True):
        """Decorator to require specific permissions."""
        if isinstance(permissions, str):
            permissions = [permissions]
        
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Get the current user from the request
                request = kwargs.get('request') or args[0] if args else None
                if not request:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Request object not found"
                    )
                
                current_user = request.state.current_user
                if not current_user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required"
                    )
                
                # Check permissions
                user_permissions = self.permission_manager.get_user_permissions(current_user.id)
                
                if require_all:
                    if not all(perm in user_permissions for perm in permissions):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Required permissions: {', '.join(permissions)}"
                        )
                else:
                    if not any(perm in user_permissions for perm in permissions):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Required permissions (any): {', '.join(permissions)}"
                        )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_roles(self, roles: Union[str, List[str]], require_all: bool = True):
        """Decorator to require specific roles."""
        if isinstance(roles, str):
            roles = [roles]
        
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Get the current user from the request
                request = kwargs.get('request') or args[0] if args else None
                if not request:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Request object not found"
                    )
                
                current_user = request.state.current_user
                if not current_user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required"
                    )
                
                # Check roles
                user_roles = self.role_manager.get_user_role_names(current_user.id)
                
                if require_all:
                    if not all(role in user_roles for role in roles):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Required roles: {', '.join(roles)}"
                        )
                else:
                    if not any(role in user_roles for role in roles):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Required roles (any): {', '.join(roles)}"
                        )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator


# Global RBAC auth instance (will be initialized with database session)
rbac_auth: Optional[RBACAuth] = None


def get_rbac_auth(db: Session) -> RBACAuth:
    """Get the RBAC auth instance."""
    global rbac_auth
    if rbac_auth is None:
        rbac_auth = RBACAuth(db)
    return rbac_auth


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(lambda: None)  # This will be injected by FastAPI
) -> User:
    """Get the current authenticated user."""
    rbac_auth = get_rbac_auth(db)
    return rbac_auth.get_current_user(credentials)


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get the current active user."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


def require_permissions(permissions: Union[str, List[str]], require_all: bool = True):
    """Decorator to require specific permissions."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get the current user from the request
            request = kwargs.get('request') or args[0] if args else None
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found"
                )
            
            current_user = request.state.current_user
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Get RBAC auth instance
            db = request.state.db
            rbac_auth = get_rbac_auth(db)
            
            # Check permissions
            user_permissions = rbac_auth.permission_manager.get_user_permissions(current_user.id)
            
            if isinstance(permissions, str):
                required_permissions = [permissions]
            else:
                required_permissions = permissions
            
            if require_all:
                if not all(perm in user_permissions for perm in required_permissions):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Required permissions: {', '.join(required_permissions)}"
                    )
            else:
                if not any(perm in user_permissions for perm in required_permissions):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Required permissions (any): {', '.join(required_permissions)}"
                    )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_roles(roles: Union[str, List[str]], require_all: bool = True):
    """Decorator to require specific roles."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get the current user from the request
            request = kwargs.get('request') or args[0] if args else None
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found"
                )
            
            current_user = request.state.current_user
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Get RBAC auth instance
            db = request.state.db
            rbac_auth = get_rbac_auth(db)
            
            # Check roles
            user_roles = rbac_auth.role_manager.get_user_role_names(current_user.id)
            
            if isinstance(roles, str):
                required_roles = [roles]
            else:
                required_roles = roles
            
            if require_all:
                if not all(role in user_roles for role in required_roles):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Required roles: {', '.join(required_roles)}"
                    )
            else:
                if not any(role in user_roles for role in required_roles):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Required roles (any): {', '.join(required_roles)}"
                    )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_superuser():
    """Decorator to require superuser privileges."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get the current user from the request
            request = kwargs.get('request') or args[0] if args else None
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found"
                )
            
            current_user = request.state.current_user
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            if not current_user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Superuser privileges required"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_resource_permission(resource: str, action: str):
    """Decorator to require permission for a specific resource and action."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get the current user from the request
            request = kwargs.get('request') or args[0] if args else None
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found"
                )
            
            current_user = request.state.current_user
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Get RBAC auth instance
            db = request.state.db
            rbac_auth = get_rbac_auth(db)
            
            # Check resource permission
            has_permission = rbac_auth.permission_manager.check_resource_permission(
                current_user.id, resource, action
            )
            
            if not has_permission:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission required: {resource}:{action}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator 
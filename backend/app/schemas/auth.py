from typing import Optional
from pydantic import BaseModel, EmailStr
from datetime import datetime


class Token(BaseModel):
    """Token response schema"""
    access_token: str
    token_type: str
    user: "UserResponse"


class TokenData(BaseModel):
    """Token data schema"""
    username: Optional[str] = None


class UserBase(BaseModel):
    """Base user schema"""
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    organization_id: Optional[int] = None


class UserCreate(UserBase):
    """User creation schema"""
    password: str


class UserUpdate(BaseModel):
    """User update schema"""
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    role: Optional[str] = None
    department: Optional[str] = None
    phone: Optional[str] = None


class UserResponse(UserBase):
    """User response schema"""
    id: int
    is_active: bool
    is_superuser: bool
    role: str
    department: Optional[str] = None
    phone: Optional[str] = None
    timezone: str
    last_login: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


# Update forward references
Token.model_rebuild() 
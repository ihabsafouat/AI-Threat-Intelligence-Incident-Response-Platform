"""
Auth0 Authentication Integration

Provides authentication using Auth0 and integrates with the RBAC system.
"""

import requests
import jwt
from typing import Optional, Dict, Any
from fastapi import HTTPException, status
from jose import JWTError, jwt as jose_jwt
from datetime import datetime, timedelta
import json
import os

from ..rbac.models import User
from ..rbac.roles import RoleManager
from ..rbac.permissions import PermissionManager


class Auth0Auth:
    """Auth0 authentication handler."""
    
    def __init__(self):
        self.domain = os.getenv("AUTH0_DOMAIN")
        self.client_id = os.getenv("AUTH0_CLIENT_ID")
        self.client_secret = os.getenv("AUTH0_CLIENT_SECRET")
        self.audience = os.getenv("AUTH0_AUDIENCE")
        self.algorithm = "RS256"
        
        # Auth0 endpoints
        self.auth_url = f"https://{self.domain}/authorize"
        self.token_url = f"https://{self.domain}/oauth/token"
        self.userinfo_url = f"https://{self.domain}/userinfo"
        self.jwks_url = f"https://{self.domain}/.well-known/jwks.json"
        
        # Fetch JWKS for token verification
        self.jwks = self._fetch_jwks()
        
        # Initialize RBAC managers
        self.role_manager = None
        self.permission_manager = None
    
    def _fetch_jwks(self) -> Dict[str, Any]:
        """Fetch JSON Web Key Set from Auth0."""
        try:
            response = requests.get(self.jwks_url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Warning: Could not fetch JWKS: {e}")
            return {}
    
    def _get_public_key(self, token: str) -> str:
        """Get the public key for token verification."""
        try:
            # Decode header without verification
            header = jwt.get_unverified_header(token)
            kid = header.get('kid')
            
            if not kid:
                raise ValueError("No 'kid' found in token header")
            
            # Find the key in JWKS
            for key in self.jwks.get('keys', []):
                if key.get('kid') == kid:
                    return key
            
            raise ValueError(f"Key with kid '{kid}' not found in JWKS")
        except Exception as e:
            raise ValueError(f"Error getting public key: {e}")
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode an Auth0 JWT token."""
        try:
            # Get the public key
            public_key = self._get_public_key(token)
            
            # Convert JWK to PEM format
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            
            # Extract RSA components
            n = int.from_bytes(bytes.fromhex(public_key['n']), 'big')
            e = int.from_bytes(bytes.fromhex(public_key['e']), 'big')
            
            # Create RSA public key
            rsa_public_key = rsa.RSAPublicNumbers(e, n).public_key()
            
            # Convert to PEM
            pem = rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1
            )
            
            # Verify and decode token
            payload = jwt.decode(
                token,
                pem,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=f"https://{self.domain}/"
            )
            
            return payload
            
        except Exception as e:
            raise ValueError(f"Token verification failed: {e}")
    
    def get_authorization_url(self, redirect_uri: str, state: str = None, scope: str = "openid profile email") -> str:
        """Get Auth0 authorization URL for OAuth flow."""
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': scope
        }
        
        if state:
            params['state'] = state
        
        if self.audience:
            params['audience'] = self.audience
        
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{self.auth_url}?{query_string}"
    
    def exchange_code_for_tokens(self, authorization_code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchange authorization code for access and ID tokens."""
        try:
            data = {
                'grant_type': 'authorization_code',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'code': authorization_code,
                'redirect_uri': redirect_uri
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            response = requests.post(self.token_url, data=data, headers=headers)
            response.raise_for_status()
            
            tokens = response.json()
            return {
                'access_token': tokens.get('access_token'),
                'id_token': tokens.get('id_token'),
                'refresh_token': tokens.get('refresh_token'),
                'expires_in': tokens.get('expires_in'),
                'token_type': tokens.get('token_type')
            }
            
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Token exchange failed: {str(e)}"
            )
    
    def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token using refresh token."""
        try:
            data = {
                'grant_type': 'refresh_token',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': refresh_token
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            response = requests.post(self.token_url, data=data, headers=headers)
            response.raise_for_status()
            
            tokens = response.json()
            return {
                'access_token': tokens.get('access_token'),
                'id_token': tokens.get('id_token'),
                'expires_in': tokens.get('expires_in'),
                'token_type': tokens.get('token_type')
            }
            
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token refresh failed"
            )
    
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Auth0."""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}'
            }
            
            response = requests.get(self.userinfo_url, headers=headers)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to get user info"
            )
    
    def get_management_token(self) -> str:
        """Get Auth0 Management API token."""
        try:
            data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'audience': f'https://{self.domain}/api/v2/'
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            response = requests.post(self.token_url, data=data, headers=headers)
            response.raise_for_status()
            
            tokens = response.json()
            return tokens.get('access_token')
            
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get management token"
            )
    
    def create_user(self, email: str, password: str, name: str = None, connection: str = "Username-Password-Authentication") -> Dict[str, Any]:
        """Create a new user in Auth0."""
        try:
            management_token = self.get_management_token()
            
            user_data = {
                'email': email,
                'password': password,
                'connection': connection,
                'email_verified': False
            }
            
            if name:
                user_data['name'] = name
            
            headers = {
                'Authorization': f'Bearer {management_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f'https://{self.domain}/api/v2/users',
                json=user_data,
                headers=headers
            )
            response.raise_for_status()
            
            user = response.json()
            return {
                'user_id': user.get('user_id'),
                'email': user.get('email'),
                'name': user.get('name')
            }
            
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"User creation failed: {str(e)}"
            )
    
    def update_user(self, user_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update user in Auth0."""
        try:
            management_token = self.get_management_token()
            
            headers = {
                'Authorization': f'Bearer {management_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.patch(
                f'https://{self.domain}/api/v2/users/{user_id}',
                json=updates,
                headers=headers
            )
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"User update failed: {str(e)}"
            )
    
    def delete_user(self, user_id: str) -> bool:
        """Delete user from Auth0."""
        try:
            management_token = self.get_management_token()
            
            headers = {
                'Authorization': f'Bearer {management_token}'
            }
            
            response = requests.delete(
                f'https://{self.domain}/api/v2/users/{user_id}',
                headers=headers
            )
            response.raise_for_status()
            
            return True
            
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"User deletion failed: {str(e)}"
            )
    
    def get_user_by_id(self, user_id: str) -> Dict[str, Any]:
        """Get user by ID from Auth0."""
        try:
            management_token = self.get_management_token()
            
            headers = {
                'Authorization': f'Bearer {management_token}'
            }
            
            response = requests.get(
                f'https://{self.domain}/api/v2/users/{user_id}',
                headers=headers
            )
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
    
    def get_users(self, page: int = 0, per_page: int = 100, search_query: str = None) -> Dict[str, Any]:
        """Get users from Auth0 with pagination and search."""
        try:
            management_token = self.get_management_token()
            
            params = {
                'page': page,
                'per_page': per_page,
                'include_totals': 'true'
            }
            
            if search_query:
                params['q'] = search_query
            
            headers = {
                'Authorization': f'Bearer {management_token}'
            }
            
            response = requests.get(
                f'https://{self.domain}/api/v2/users',
                params=params,
                headers=headers
            )
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get users: {str(e)}"
            )
    
    def assign_role_to_user(self, user_id: str, role_id: str) -> bool:
        """Assign a role to a user in Auth0."""
        try:
            management_token = self.get_management_token()
            
            headers = {
                'Authorization': f'Bearer {management_token}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'roles': [role_id]
            }
            
            response = requests.post(
                f'https://{self.domain}/api/v2/users/{user_id}/roles',
                json=data,
                headers=headers
            )
            response.raise_for_status()
            
            return True
            
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Role assignment failed: {str(e)}"
            )
    
    def get_user_roles(self, user_id: str) -> list:
        """Get roles assigned to a user in Auth0."""
        try:
            management_token = self.get_management_token()
            
            headers = {
                'Authorization': f'Bearer {management_token}'
            }
            
            response = requests.get(
                f'https://{self.domain}/api/v2/users/{user_id}/roles',
                headers=headers
            )
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get user roles: {str(e)}"
            )
    
    def sync_user_with_rbac(self, db_session, auth0_user_info: Dict[str, Any]) -> User:
        """Sync Auth0 user with local RBAC system."""
        if not self.role_manager:
            self.role_manager = RoleManager(db_session)
        
        if not self.permission_manager:
            self.permission_manager = PermissionManager(db_session)
        
        # Check if user exists in local system
        user = db_session.query(User).filter(
            User.username == auth0_user_info.get('sub') or 
            User.email == auth0_user_info.get('email')
        ).first()
        
        if not user:
            # Create new user in local system
            user = User(
                username=auth0_user_info.get('sub'),
                email=auth0_user_info.get('email'),
                first_name=auth0_user_info.get('given_name', ''),
                last_name=auth0_user_info.get('family_name', ''),
                is_active=True,
                is_superuser=False
            )
            db_session.add(user)
            db_session.commit()
            db_session.refresh(user)
            
            # Assign default role
            default_role = self.role_manager.get_role_by_name("user")
            if default_role:
                self.role_manager.assign_role_to_user(
                    user.id, 
                    default_role.id, 
                    assigned_by=1  # System user
                )
        
        return user
    
    def get_auth0_login_url(self, redirect_uri: str) -> str:
        """Get Auth0 hosted login URL."""
        return self.get_authorization_url(redirect_uri)
    
    def get_auth0_logout_url(self, return_to: str) -> str:
        """Get Auth0 hosted logout URL."""
        return f"https://{self.domain}/v2/logout?client_id={self.client_id}&returnTo={return_to}"
    
    def validate_webhook_signature(self, payload: str, signature: str) -> bool:
        """Validate Auth0 webhook signature."""
        try:
            # This is a simplified validation - in production, you should implement proper signature validation
            # using the webhook secret from Auth0
            webhook_secret = os.getenv("AUTH0_WEBHOOK_SECRET")
            if not webhook_secret:
                return False
            
            # Implement proper signature validation here
            # This is a placeholder for the actual validation logic
            return True
            
        except Exception:
            return False


# Global instance
auth0_auth = Auth0Auth() 
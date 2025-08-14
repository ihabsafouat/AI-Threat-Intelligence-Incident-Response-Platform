"""
AWS Cognito Authentication Integration

Provides authentication using AWS Cognito User Pools and integrates with the RBAC system.
"""

import boto3
import jwt
import requests
from typing import Optional, Dict, Any
from fastapi import HTTPException, status
from botocore.exceptions import ClientError
from jose import JWTError, jwt as jose_jwt
from datetime import datetime, timedelta
import json
import os

from ..rbac.models import User
from ..rbac.roles import RoleManager
from ..rbac.permissions import PermissionManager


class CognitoAuth:
    """AWS Cognito authentication handler."""
    
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "us-east-1")
        self.user_pool_id = os.getenv("COGNITO_USER_POOL_ID")
        self.client_id = os.getenv("COGNITO_CLIENT_ID")
        self.client_secret = os.getenv("COGNITO_CLIENT_SECRET", None)
        self.domain = os.getenv("COGNITO_DOMAIN")
        
        # Initialize Cognito client
        self.cognito_client = boto3.client(
            'cognito-idp',
            region_name=self.region
        )
        
        # Get JWKS for token verification
        self.jwks_url = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json"
        self.jwks = self._fetch_jwks()
        
        # Initialize RBAC managers
        self.role_manager = None
        self.permission_manager = None
    
    def _fetch_jwks(self) -> Dict[str, Any]:
        """Fetch JSON Web Key Set from Cognito."""
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
        """Verify and decode a Cognito JWT token."""
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
                algorithms=['RS256'],
                audience=self.client_id,
                issuer=f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"
            )
            
            return payload
            
        except Exception as e:
            raise ValueError(f"Token verification failed: {e}")
    
    def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user with Cognito."""
        try:
            # Initiate authentication
            auth_params = {
                'USERNAME': username,
                'PASSWORD': password
            }
            
            if self.client_secret:
                auth_params['SECRET_HASH'] = self._calculate_secret_hash(username)
            
            response = self.cognito_client.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                ClientId=self.client_id,
                AuthParameters=auth_params
            )
            
            if response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
                return {
                    'challenge': 'NEW_PASSWORD_REQUIRED',
                    'session': response['Session'],
                    'username': username
                }
            
            return {
                'access_token': response['AuthenticationResult']['AccessToken'],
                'id_token': response['AuthenticationResult']['IdToken'],
                'refresh_token': response['AuthenticationResult']['RefreshToken'],
                'expires_in': response['AuthenticationResult']['ExpiresIn']
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NotAuthorizedException':
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )
            elif error_code == 'UserNotConfirmedException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User account not confirmed"
                )
            elif error_code == 'UserNotFoundException':
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Authentication error: {error_code}"
                )
    
    def complete_new_password_challenge(self, username: str, new_password: str, session: str) -> Dict[str, Any]:
        """Complete new password challenge."""
        try:
            auth_params = {
                'USERNAME': username,
                'NEW_PASSWORD': new_password
            }
            
            if self.client_secret:
                auth_params['SECRET_HASH'] = self._calculate_secret_hash(username)
            
            response = self.cognito_client.respond_to_auth_challenge(
                ClientId=self.client_id,
                ChallengeName='NEW_PASSWORD_REQUIRED',
                Session=session,
                ChallengeResponses=auth_params
            )
            
            return {
                'access_token': response['AuthenticationResult']['AccessToken'],
                'id_token': response['AuthenticationResult']['IdToken'],
                'refresh_token': response['AuthenticationResult']['RefreshToken'],
                'expires_in': response['AuthenticationResult']['ExpiresIn']
            }
            
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password change failed: {e.response['Error']['Message']}"
            )
    
    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token using refresh token."""
        try:
            auth_params = {
                'REFRESH_TOKEN': refresh_token
            }
            
            if self.client_secret:
                # Note: For refresh token, we need the username from the token
                # This is a limitation of Cognito
                pass
            
            response = self.cognito_client.initiate_auth(
                AuthFlow='REFRESH_TOKEN_AUTH',
                ClientId=self.client_id,
                AuthParameters=auth_params
            )
            
            return {
                'access_token': response['AuthenticationResult']['AccessToken'],
                'id_token': response['AuthenticationResult']['IdToken'],
                'expires_in': response['AuthenticationResult']['ExpiresIn']
            }
            
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
    
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Cognito."""
        try:
            response = self.cognito_client.get_user(
                AccessToken=access_token
            )
            
            user_info = {}
            for attr in response['UserAttributes']:
                user_info[attr['Name']] = attr['Value']
            
            return user_info
            
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid access token"
            )
    
    def create_user(self, username: str, email: str, password: str, attributes: Dict[str, str] = None) -> Dict[str, Any]:
        """Create a new user in Cognito."""
        try:
            user_attributes = [
                {
                    'Name': 'email',
                    'Value': email
                }
            ]
            
            # Add custom attributes
            if attributes:
                for key, value in attributes.items():
                    user_attributes.append({
                        'Name': key,
                        'Value': value
                    })
            
            response = self.cognito_client.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=username,
                UserAttributes=user_attributes,
                TemporaryPassword=password,
                MessageAction='SUPPRESS'  # Suppress welcome email
            )
            
            return {
                'user_id': response['User']['Username'],
                'email': email,
                'status': response['User']['UserStatus']
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'UsernameExistsException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already exists"
                )
            elif error_code == 'InvalidPasswordException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Password does not meet requirements"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"User creation failed: {error_code}"
                )
    
    def confirm_user(self, username: str, confirmation_code: str) -> bool:
        """Confirm user registration."""
        try:
            self.cognito_client.confirm_sign_up(
                ClientId=self.client_id,
                Username=username,
                ConfirmationCode=confirmation_code
            )
            return True
            
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Confirmation failed: {e.response['Error']['Message']}"
            )
    
    def reset_password(self, username: str) -> bool:
        """Initiate password reset."""
        try:
            self.cognito_client.forgot_password(
                ClientId=self.client_id,
                Username=username
            )
            return True
            
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password reset failed: {e.response['Error']['Message']}"
            )
    
    def confirm_reset_password(self, username: str, confirmation_code: str, new_password: str) -> bool:
        """Confirm password reset."""
        try:
            self.cognito_client.confirm_forgot_password(
                ClientId=self.client_id,
                Username=username,
                ConfirmationCode=confirmation_code,
                Password=new_password
            )
            return True
            
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password reset confirmation failed: {e.response['Error']['Message']}"
            )
    
    def _calculate_secret_hash(self, username: str) -> str:
        """Calculate secret hash for Cognito authentication."""
        if not self.client_secret:
            return None
        
        import hashlib
        import hmac
        import base64
        
        message = username + self.client_id
        digest = hmac.new(
            str(self.client_secret).encode('utf-8'),
            msg=message.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        
        return base64.b64encode(digest).decode()
    
    def sync_user_with_rbac(self, db_session, cognito_user_info: Dict[str, Any]) -> User:
        """Sync Cognito user with local RBAC system."""
        if not self.role_manager:
            self.role_manager = RoleManager(db_session)
        
        if not self.permission_manager:
            self.permission_manager = PermissionManager(db_session)
        
        # Check if user exists in local system
        user = db_session.query(User).filter(
            User.username == cognito_user_info.get('sub') or 
            User.email == cognito_user_info.get('email')
        ).first()
        
        if not user:
            # Create new user in local system
            user = User(
                username=cognito_user_info.get('sub'),
                email=cognito_user_info.get('email'),
                first_name=cognito_user_info.get('given_name', ''),
                last_name=cognito_user_info.get('family_name', ''),
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
    
    def get_cognito_login_url(self) -> str:
        """Get Cognito hosted UI login URL."""
        if not self.domain:
            return None
        
        return f"https://{self.domain}/login?client_id={self.client_id}&response_type=code&scope=openid+email+profile&redirect_uri={os.getenv('COGNITO_REDIRECT_URI')}"
    
    def get_cognito_logout_url(self) -> str:
        """Get Cognito hosted UI logout URL."""
        if not self.domain:
            return None
        
        return f"https://{self.domain}/logout?client_id={self.client_id}&logout_uri={os.getenv('COGNITO_LOGOUT_URI')}"


# Global instance
cognito_auth = CognitoAuth() 
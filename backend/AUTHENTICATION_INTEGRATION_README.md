# Authentication Integration Guide

This guide explains how to integrate AWS Cognito or Auth0 authentication with your FastAPI application and RBAC system.

## Overview

The authentication system provides a unified interface for three authentication providers:

1. **Local Authentication** - JWT-based authentication using your existing RBAC system
2. **AWS Cognito** - Managed authentication service from AWS
3. **Auth0** - Enterprise-grade authentication platform

All providers integrate seamlessly with your existing RBAC system, ensuring consistent authorization across your application.

## Features

### 🔐 **Multi-Provider Support**
- **AWS Cognito**: Full user management, MFA, social login
- **Auth0**: Advanced authentication, rules, hooks, organizations
- **Local**: Custom JWT authentication with RBAC

### 🔄 **Seamless RBAC Integration**
- Automatic user synchronization between external providers and local RBAC
- Consistent permission checking across all authentication methods
- Role-based access control maintained regardless of auth provider

### 🚀 **OAuth 2.0 & OpenID Connect**
- Standard OAuth flows for web and mobile applications
- Secure token management with automatic refresh
- Webhook support for real-time user synchronization

### 🛡️ **Security Features**
- JWT token verification with proper signature validation
- Secure password handling and reset flows
- Webhook signature validation for Auth0
- Configurable CORS and host restrictions

## Quick Start

### 1. Choose Your Provider

Set the `AUTH_PROVIDER` environment variable:

```bash
# For AWS Cognito
AUTH_PROVIDER=cognito

# For Auth0
AUTH_PROVIDER=auth0

# For local authentication
AUTH_PROVIDER=local
```

### 2. Configure Environment Variables

#### AWS Cognito Configuration

```bash
# Required
AWS_REGION=us-east-1
COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
COGNITO_DOMAIN=your-domain.auth.us-east-1.amazoncognito.com

# Optional
COGNITO_CLIENT_SECRET=your-client-secret
COGNITO_REDIRECT_URI=http://localhost:3000/auth/callback
COGNITO_LOGOUT_URI=http://localhost:3000
```

#### Auth0 Configuration

```bash
# Required
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_AUDIENCE=your-api-identifier

# Optional
AUTH0_WEBHOOK_SECRET=your-webhook-secret
```

### 3. Install Dependencies

```bash
pip install boto3 requests cryptography
```

### 4. Use in Your Endpoints

```python
from app.core.auth.service import get_current_user

@router.get("/protected")
async def protected_endpoint(current_user = Depends(get_current_user)):
    return {"message": f"Hello {current_user.username}!"}
```

## Detailed Configuration

### AWS Cognito Setup

#### 1. Create Cognito User Pool

1. Go to AWS Console → Cognito → User Pools
2. Create a new user pool
3. Configure app client with appropriate settings
4. Note down the User Pool ID and Client ID

#### 2. Configure App Client

- **Authentication flows**: Enable `USER_PASSWORD_AUTH` for direct login
- **OAuth flows**: Enable authorization code flow
- **Callback URLs**: Add your application's callback URL
- **Sign out URLs**: Add your application's logout URL

#### 3. Set Up Domain

1. Create a custom domain or use the provided domain
2. Configure the domain in your environment variables

#### 4. Environment Variables

```bash
export AUTH_PROVIDER=cognito
export AWS_REGION=us-east-1
export COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
export COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
export COGNITO_DOMAIN=your-domain.auth.us-east-1.amazoncognito.com
export COGNITO_REDIRECT_URI=http://localhost:3000/auth/callback
export COGNITO_LOGOUT_URI=http://localhost:3000
```

### Auth0 Setup

#### 1. Create Auth0 Application

1. Go to Auth0 Dashboard → Applications
2. Create a new application (Regular Web Application)
3. Configure callback URLs and logout URLs
4. Note down the Client ID and Client Secret

#### 2. Configure API

1. Go to APIs section
2. Create a new API or use the default
3. Note down the API identifier (audience)

#### 3. Set Up Rules (Optional)

Create Auth0 rules for custom user attributes or business logic:

```javascript
function (user, context, callback) {
  // Add custom claims to the token
  context.idToken['https://your-domain.com/roles'] = user.app_metadata.roles;
  context.accessToken['https://your-domain.com/roles'] = user.app_metadata.roles;
  
  callback(null, user, context);
}
```

#### 4. Environment Variables

```bash
export AUTH_PROVIDER=auth0
export AUTH0_DOMAIN=your-domain.auth0.com
export AUTH0_CLIENT_ID=your-client-id
export AUTH0_CLIENT_SECRET=your-client-secret
export AUTH0_AUDIENCE=your-api-identifier
export AUTH0_WEBHOOK_SECRET=your-webhook-secret
```

## API Endpoints

### Authentication Endpoints

#### OAuth Flow

- `GET /auth/external/login` - Get login URL
- `GET /auth/external/callback` - Handle OAuth callback
- `GET /auth/external/logout` - Get logout URL

#### Direct Authentication (Cognito)

- `POST /auth/external/login/direct` - Username/password login
- `POST /auth/external/login/new-password` - Complete new password challenge

#### Token Management

- `POST /auth/external/refresh` - Refresh access token

#### User Management

- `POST /auth/external/users` - Create user
- `GET /auth/external/users/{user_id}` - Get user
- `PUT /auth/external/users/{user_id}` - Update user
- `DELETE /auth/external/users/{user_id}` - Delete user

#### Password Management

- `POST /auth/external/users/{user_id}/reset-password` - Reset password
- `POST /auth/external/users/{user_id}/confirm-reset-password` - Confirm password reset

#### Provider Information

- `GET /auth/external/provider/info` - Get provider information
- `GET /auth/external/provider/status` - Get provider status

#### Webhooks

- `POST /auth/external/webhooks/auth0` - Handle Auth0 webhooks

## Usage Examples

### Frontend Integration

#### React Example

```jsx
import { useEffect, useState } from 'react';

function Login() {
  const [loginUrl, setLoginUrl] = useState('');
  
  useEffect(() => {
    // Get login URL from your API
    fetch('/api/v1/auth/external/login?redirect_uri=' + encodeURIComponent(window.location.origin + '/auth/callback'))
      .then(res => res.json())
      .then(data => setLoginUrl(data.login_url));
  }, []);
  
  return (
    <div>
      <a href={loginUrl} className="btn btn-primary">
        Login with {process.env.REACT_APP_AUTH_PROVIDER}
      </a>
    </div>
  );
}
```

#### Vue.js Example

```vue
<template>
  <div>
    <a :href="loginUrl" class="btn btn-primary">
      Login with {{ authProvider }}
    </a>
  </div>
</template>

<script>
export default {
  data() {
    return {
      loginUrl: '',
      authProvider: process.env.VUE_APP_AUTH_PROVIDER
    }
  },
  async mounted() {
    const response = await fetch(`/api/v1/auth/external/login?redirect_uri=${encodeURIComponent(window.location.origin + '/auth/callback')}`);
    const data = await response.json();
    this.loginUrl = data.login_url;
  }
}
</script>
```

### Backend Integration

#### Custom Authentication Logic

```python
from app.core.auth.service import unified_auth, get_current_user
from app.core.rbac import require_permissions

@router.post("/custom-auth")
async def custom_authentication(
    username: str,
    password: str,
    db: Session = Depends(get_db_session)
):
    """Custom authentication with external provider."""
    try:
        # Authenticate with configured provider
        result = unified_auth.authenticate_user(username, password)
        
        # Get user info and sync with RBAC
        user = unified_auth.get_current_user(result["access_token"], db)
        
        return {
            "message": "Authentication successful",
            "user": user,
            "tokens": result
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}"
        )

@router.get("/protected-resource")
@require_permissions(["resource:read"])
async def protected_resource(
    current_user = Depends(get_current_user)
):
    """Protected endpoint using RBAC."""
    return {
        "message": "Access granted",
        "user": current_user.username,
        "permissions": [p.name for p in current_user.permissions]
    }
```

## RBAC Integration

### Automatic User Synchronization

When a user authenticates through an external provider:

1. **Token Verification**: The system verifies the JWT token with the provider
2. **User Info Retrieval**: Fetches user information from the provider
3. **Local User Creation**: Creates or updates the user in your local RBAC system
4. **Role Assignment**: Assigns default roles to new users
5. **Permission Checking**: All subsequent requests use your local RBAC system

### Custom Role Mapping

You can customize how external provider roles map to your RBAC system:

```python
from app.core.auth.cognito import cognito_auth

def sync_user_with_custom_roles(db_session, cognito_user_info):
    """Custom user synchronization with role mapping."""
    user = cognito_user_info.sync_user_with_rbac(db_session, cognito_user_info)
    
    # Map Cognito groups to local roles
    cognito_groups = cognito_user_info.get('cognito:groups', [])
    
    if 'admin' in cognito_groups:
        # Assign admin role
        role_manager = RoleManager(db_session)
        admin_role = role_manager.get_role_by_name("admin")
        if admin_role:
            role_manager.assign_role_to_user(user.id, admin_role.id, assigned_by=1)
    
    return user
```

## Security Considerations

### Token Security

- **JWT Verification**: All tokens are verified using provider public keys
- **Signature Validation**: Ensures tokens haven't been tampered with
- **Expiration Checking**: Automatic token expiration handling
- **Audience Validation**: Verifies tokens are intended for your application

### Webhook Security

- **Signature Validation**: Auth0 webhooks are validated using webhook secrets
- **HTTPS Only**: All webhook endpoints should use HTTPS in production
- **IP Whitelisting**: Consider whitelisting provider IP addresses

### CORS Configuration

```python
from fastapi.middleware.cors import CORSMiddleware
from app.core.auth.config import get_auth_config

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_auth_config().get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## Monitoring and Debugging

### Provider Status Endpoint

```bash
curl /api/v1/auth/external/provider/status
```

Response:
```json
{
  "provider": "cognito",
  "configured": true,
  "status": "healthy",
  "features": {
    "username_password_auth": true,
    "oauth_flow": true,
    "social_login": true,
    "mfa": true,
    "user_management": true,
    "role_management": true
  }
}
```

### Configuration Validation

```python
from app.core.auth.config import validate_auth_configuration

# Validate configuration
validation = validate_auth_configuration()
if validation["errors"]:
    print("Configuration errors:", validation["errors"])
if validation["warnings"]:
    print("Configuration warnings:", validation["warnings"])
```

### Logging

Enable debug logging to troubleshoot authentication issues:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Log authentication events
logger.info(f"User authenticated: {user.username}")
logger.debug(f"Token payload: {payload}")
```

## Troubleshooting

### Common Issues

#### 1. Token Verification Failed

**Symptoms**: 401 Unauthorized errors
**Causes**: 
- Invalid token signature
- Expired token
- Wrong audience or issuer
- Provider configuration issues

**Solutions**:
- Check provider configuration
- Verify token expiration
- Ensure correct audience/issuer values

#### 2. User Synchronization Issues

**Symptoms**: Users not appearing in local system
**Causes**:
- Database connection issues
- RBAC system not initialized
- Permission issues

**Solutions**:
- Check database connectivity
- Verify RBAC system setup
- Check user permissions

#### 3. OAuth Flow Errors

**Symptoms**: Login redirects failing
**Causes**:
- Incorrect callback URLs
- Missing client configuration
- Provider setup issues

**Solutions**:
- Verify callback URLs in provider settings
- Check client ID and secret
- Ensure proper OAuth flow configuration

### Debug Mode

Enable debug mode for detailed error information:

```python
import os
os.environ["DEBUG"] = "true"

# This will provide detailed error messages and stack traces
```

## Performance Optimization

### Token Caching

Implement token caching to reduce provider API calls:

```python
from functools import lru_cache
import time

@lru_cache(maxsize=1000)
def get_cached_user_info(user_id: str, cache_time: int = 300):
    """Cache user info for 5 minutes."""
    return cognito_auth.get_user_by_id(user_id)

# Use cached version
user_info = get_cached_user_info(user_id, int(time.time() / 300))
```

### Connection Pooling

For high-traffic applications, configure connection pooling:

```python
import boto3
from botocore.config import Config

# Configure Cognito client with connection pooling
config = Config(
    region_name='us-east-1',
    max_pool_connections=50,
    retries={'max_attempts': 3}
)

cognito_client = boto3.client('cognito-idp', config=config)
```

## Migration Guide

### From Local to External Authentication

1. **Backup Current Users**: Export existing user data
2. **Configure Provider**: Set up Cognito or Auth0
3. **Update Environment**: Change AUTH_PROVIDER
4. **Migrate Users**: Create users in external provider
5. **Test Authentication**: Verify login flows
6. **Update Frontend**: Modify login/logout logic

### From One Provider to Another

1. **Export Users**: Export users from current provider
2. **Configure New Provider**: Set up new authentication service
3. **Import Users**: Create users in new provider
4. **Update Configuration**: Change environment variables
5. **Test Migration**: Verify all authentication flows
6. **Update Documentation**: Update team documentation

## Best Practices

### 1. **Environment Management**
- Use different configurations for development, staging, and production
- Never commit secrets to version control
- Use environment-specific .env files

### 2. **Error Handling**
- Implement proper error handling for authentication failures
- Log authentication events for security monitoring
- Provide user-friendly error messages

### 3. **Security**
- Regularly rotate client secrets
- Use HTTPS in production
- Implement proper session management
- Monitor for suspicious authentication patterns

### 4. **Testing**
- Test authentication flows in all environments
- Mock external providers in unit tests
- Test error scenarios and edge cases

### 5. **Documentation**
- Document provider-specific configurations
- Maintain troubleshooting guides
- Keep team updated on authentication changes

## Support and Resources

### AWS Cognito Resources
- [AWS Cognito Documentation](https://docs.aws.amazon.com/cognito/)
- [Cognito User Pool API Reference](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/)
- [AWS Cognito Best Practices](https://docs.aws.amazon.com/cognito/latest/developerguide/best-practices.html)

### Auth0 Resources
- [Auth0 Documentation](https://auth0.com/docs)
- [Auth0 Management API](https://auth0.com/docs/api/management/v2)
- [Auth0 Rules and Hooks](https://auth0.com/docs/rules)

### General OAuth Resources
- [OAuth 2.0 Specification](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Specification](https://openid.net/connect/)
- [JWT Specification](https://tools.ietf.org/html/rfc7519)

## Conclusion

This authentication integration provides a robust, secure, and flexible authentication system that works seamlessly with your existing RBAC implementation. Whether you choose AWS Cognito, Auth0, or local authentication, you'll have enterprise-grade security with the flexibility to adapt to your specific needs.

The system automatically handles user synchronization, token management, and permission checking, allowing you to focus on building your application's core functionality while maintaining strong security practices. 
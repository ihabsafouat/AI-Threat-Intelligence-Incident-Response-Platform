# Role-Based Access Control (RBAC) System

This document describes the comprehensive RBAC system implemented in the Threat Intelligence Platform.

## Overview

The RBAC system provides fine-grained access control for all platform resources, ensuring that users can only access and modify data they're authorized to work with. The system is built on three core concepts:

- **Users**: Individuals who access the system
- **Roles**: Collections of permissions that define what actions users can perform
- **Permissions**: Granular access rights for specific resources and actions

## Architecture

### Core Components

1. **RBAC Models** (`app/core/rbac/models.py`)
   - Database models for users, roles, permissions, and their relationships
   - Association tables for many-to-many relationships
   - Pydantic models for API requests/responses

2. **Permission Management** (`app/core/rbac/permissions.py`)
   - Predefined permission constants
   - Permission manager for CRUD operations
   - User permission checking logic

3. **Role Management** (`app/core/rbac/roles.py`)
   - Predefined role constants
   - Role manager for CRUD operations
   - User-role assignment logic

4. **Authentication** (`app/core/rbac/auth.py`)
   - JWT token management
   - Password hashing and verification
   - User authentication logic

5. **Middleware** (`app/core/rbac/middleware.py`)
   - RBAC middleware for request processing
   - Permission checking at the middleware level

6. **Database** (`app/core/rbac/database.py`)
   - Database operations for RBAC entities
   - Connection management and session handling

## Predefined Roles

### System Roles
- **super_admin**: Full system access
- **admin**: Administrative access
- **user**: Basic user access

### Security Roles
- **security_analyst**: Threat analysis and incident response
- **threat_hunter**: Advanced threat hunting
- **incident_responder**: Incident management
- **soc_analyst**: Security operations center analyst

### Management Roles
- **security_manager**: Security team management
- **it_manager**: IT infrastructure management
- **compliance_officer**: Compliance and audit

### Technical Roles
- **system_admin**: System administration
- **developer**: Application development
- **data_analyst**: Data analysis and reporting
- **researcher**: Security research

### Read-only Roles
- **viewer**: Read-only access to most resources
- **reporter**: Access to reports and analytics
- **auditor**: Audit and compliance access

## Predefined Permissions

### User Management
- `user:read` - View user information
- `user:create` - Create new users
- `user:update` - Modify user information
- `user:delete` - Remove users
- `user:assign_roles` - Assign roles to users

### Role Management
- `role:read` - View role information
- `role:create` - Create new roles
- `role:update` - Modify role information
- `role:delete` - Remove roles
- `role:assign_permissions` - Assign permissions to roles

### Permission Management
- `permission:read` - View permission information
- `permission:create` - Create new permissions
- `permission:update` - Modify permission information
- `permission:delete` - Remove permissions

### Threat Intelligence
- `threat:read` - View threat information
- `threat:create` - Create new threats
- `threat:update` - Modify threat information
- `threat:delete` - Remove threats
- `threat:analyze` - Analyze threats with AI
- `threat:export` - Export threat data

### Incident Response
- `incident:read` - View incident information
- `incident:create` - Create new incidents
- `incident:update` - Modify incident information
- `incident:delete` - Remove incidents

### Analytics and Reporting
- `analytics:read` - Access analytics data
- `analytics:create` - Create analytics reports
- `analytics:update` - Modify analytics reports
- `analytics:delete` - Remove analytics reports
- `analytics:export` - Export analytics data

### Machine Learning
- `ml:read` - View ML model information
- `ml:create` - Create new ML models
- `ml:update` - Modify ML models
- `ml:delete` - Remove ML models

## API Endpoints

### RBAC Management (`/api/v1/rbac`)

#### Role Management
- `GET /rbac/roles` - List all roles
- `GET /rbac/roles/{role_id}` - Get specific role
- `POST /rbac/roles` - Create new role
- `PUT /rbac/roles/{role_id}` - Update role
- `DELETE /rbac/roles/{role_id}` - Delete role

#### Permission Management
- `GET /rbac/permissions` - List all permissions
- `GET /rbac/permissions/{permission_id}` - Get specific permission
- `POST /rbac/permissions` - Create new permission
- `PUT /rbac/permissions/{permission_id}` - Update permission
- `DELETE /rbac/permissions/{permission_id}` - Delete permission

#### User-Role Assignment
- `GET /rbac/users/{user_id}/roles` - Get user's roles
- `POST /rbac/users/{user_id}/roles` - Assign role to user
- `DELETE /rbac/users/{user_id}/roles/{role_id}` - Remove role from user

#### Role-Permission Assignment
- `GET /rbac/roles/{role_id}/permissions` - Get role's permissions
- `POST /rbac/roles/{role_id}/permissions` - Assign permission to role
- `DELETE /rbac/roles/{role_id}/permissions/{permission_id}` - Remove permission from role

#### Utility Endpoints
- `GET /rbac/users/{user_id}/permissions` - Get user's effective permissions
- `GET /rbac/check-permission` - Check if user has specific permission
- `GET /rbac/check-role` - Check if user has specific role

### User Management (`/api/v1/users`)

#### User Operations
- `GET /users` - List users (with pagination)
- `GET /users/me` - Get current user info
- `GET /users/{user_id}` - Get specific user
- `POST /users` - Create new user
- `PUT /users/{user_id}` - Update user
- `DELETE /users/{user_id}` - Delete user (soft delete)

#### User Management
- `PATCH /users/{user_id}/activate` - Activate user
- `PATCH /users/{user_id}/deactivate` - Deactivate user
- `PATCH /users/{user_id}/reset-password` - Reset user password
- `GET /users/search` - Search users
- `GET /users/{user_id}/profile` - Get detailed user profile

### Threat Intelligence (`/api/v1/threats`)

#### Threat Operations
- `GET /threats` - List threats (with filtering)
- `GET /threats/{threat_id}` - Get specific threat
- `POST /threats` - Create new threat
- `PUT /threats/{threat_id}` - Update threat
- `DELETE /threats/{threat_id}` - Delete threat

#### Advanced Operations
- `POST /threats/{threat_id}/analyze` - Analyze threat with AI
- `POST /threats/{threat_id}/export` - Export threat data
- `GET /threats/search` - Search threats
- `GET /threats/statistics/summary` - Get threat statistics
- `POST /threats/bulk-import` - Bulk import threats
- `POST /threats/{threat_id}/share` - Share threat with users

### Incident Response (`/api/v1/incidents`)

#### Incident Operations
- `GET /incidents` - List incidents (with filtering)
- `GET /incidents/{incident_id}` - Get specific incident
- `POST /incidents` - Create new incident
- `PUT /incidents/{incident_id}` - Update incident
- `DELETE /incidents/{incident_id}` - Delete incident

#### Incident Management
- `POST /incidents/{incident_id}/assign` - Assign incident to user
- `POST /incidents/{incident_id}/escalate` - Escalate incident priority
- `POST /incidents/{incident_id}/close` - Close incident
- `GET /incidents/search` - Search incidents
- `GET /incidents/statistics/summary` - Get incident statistics
- `POST /incidents/bulk-close` - Bulk close incidents
- `GET /incidents/my-incidents` - Get user's assigned incidents

### Analytics (`/api/v1/analytics`)

#### Dashboard and Metrics
- `GET /analytics/dashboard/overview` - Dashboard overview
- `GET /analytics/threats/trends` - Threat trends over time
- `GET /analytics/incidents/performance` - Incident response performance
- `GET /analytics/vulnerabilities/risk-assessment` - Vulnerability risk assessment
- `GET /analytics/assets/security-posture` - Asset security posture

#### Reporting
- `GET /analytics/reports/security-summary` - Generate security summary report
- `POST /analytics/reports/export` - Export analytics report
- `GET /analytics/metrics/real-time` - Real-time security metrics
- `GET /analytics/comparison/period` - Compare metrics between periods

### Machine Learning (`/api/v1/ml`)

#### Model Management
- `GET /ml/models/status` - Get ML model status
- `POST /ml/models/train` - Train ML model
- `GET /ml/models/{model_name}/performance` - Get model performance
- `POST /ml/models/deploy` - Deploy ML model
- `GET /ml/models/{model_name}/logs` - Get model logs
- `POST /ml/models/retrain` - Retrain ML model
- `DELETE /ml/models/{model_name}` - Delete ML model

#### AI-Powered Analysis
- `POST /ml/threats/analyze` - Analyze threats with AI
- `POST /ml/incidents/predict` - Predict incident impact
- `POST /ml/vulnerabilities/prioritize` - Prioritize vulnerabilities with AI
- `GET /ml/ai/insights` - Get AI-generated insights

## Usage Examples

### Protecting Endpoints with Permissions

```python
from app.core.rbac import require_permissions

@router.get("/protected-endpoint")
@require_permissions(["threat:read"])
async def protected_endpoint(current_user = Depends(get_current_user)):
    # Only users with threat:read permission can access this
    pass
```

### Requiring Multiple Permissions

```python
@router.post("/advanced-operation")
@require_permissions(["threat:create", "threat:analyze"])
async def advanced_operation(current_user = Depends(get_current_user)):
    # User must have both permissions
    pass
```

### Role-Based Access

```python
from app.core.rbac import require_roles

@router.get("/admin-only")
@require_roles(["admin", "super_admin"])
async def admin_endpoint(current_user = Depends(get_current_user)):
    # Only admin roles can access this
    pass
```

### Checking Permissions in Code

```python
from app.core.rbac.permissions import PermissionManager

permission_manager = PermissionManager(db)
if permission_manager.user_has_permission(user_id, "threat:delete"):
    # User can delete threats
    pass
```

## Database Schema

### Core Tables

1. **users** - User accounts
2. **roles** - Role definitions
3. **permissions** - Permission definitions
4. **user_roles** - User-role assignments
5. **role_permissions** - Role-permission assignments

### Key Fields

- **users**: id, username, email, hashed_password, is_active, is_superuser
- **roles**: id, name, description, is_active
- **permissions**: id, name, description, resource, action, is_active
- **user_roles**: user_id, role_id, assigned_at, assigned_by, expires_at
- **role_permissions**: role_id, permission_id, granted_at, granted_by, expires_at

## Security Features

### Authentication
- JWT token-based authentication
- Password hashing with bcrypt
- Token expiration and refresh
- Failed login attempt tracking

### Authorization
- Fine-grained permission checking
- Role-based access control
- Resource-level permissions
- Action-level permissions

### Audit Trail
- All role and permission assignments are logged
- User activity tracking
- Change history for RBAC entities

## Best Practices

### Permission Design
1. Use resource:action format (e.g., `threat:read`)
2. Keep permissions granular but not overly specific
3. Group related permissions into roles
4. Use descriptive permission names

### Role Design
1. Create roles based on job functions
2. Limit the number of roles per user
3. Use role hierarchies when appropriate
4. Regularly review and update role assignments

### Security Considerations
1. Follow principle of least privilege
2. Regularly audit user permissions
3. Implement role expiration where appropriate
4. Monitor for unusual permission patterns

## Configuration

### Environment Variables

```bash
# JWT Configuration
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost/dbname

# Security Configuration
ALLOWED_HOSTS=localhost,127.0.0.1
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
```

### Database Initialization

The system automatically creates default roles and permissions on startup. You can customize the initial setup by modifying the RBAC initialization code.

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Check if user has required permissions
   - Verify role assignments
   - Check permission definitions

2. **Authentication Issues**
   - Verify JWT token validity
   - Check token expiration
   - Validate user account status

3. **Database Connection Issues**
   - Verify database configuration
   - Check connection pool settings
   - Validate database permissions

### Debug Mode

Enable debug logging by setting the appropriate log level in your configuration.

## Contributing

When adding new endpoints or functionality:

1. Define appropriate permissions
2. Use the `@require_permissions` decorator
3. Update this documentation
4. Add appropriate tests
5. Follow the established RBAC patterns

## Support

For questions or issues with the RBAC system:

1. Check this documentation
2. Review the API endpoints
3. Examine the source code
4. Create an issue in the project repository 
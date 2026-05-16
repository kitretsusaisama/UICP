# UICP API Documentation

## Overview

UICP is a domain-aware, API-key-centric multi-tenant identity and communication platform.

**Design Pattern:** Auth0 / Clerk / Firebase style - tenant context derived from credentials, not headers.

---

## Authentication

### Credential Types

| Type | Prefix | Purpose | Usage |
|------|--------|---------|-------|
| Live Publishable | `uF{ULID26}xl` | Client-side API calls | Frontend, mobile apps |
| Live Secret | `sF{ULID26}xl{HMAC44}` | Server-side API calls | Backend services, SDKs |
| Dev Publishable | `pB{ULID26}` | Development | Local testing |
| Dev Secret | `tB{ULID26}{HMAC44}` | Development | Local testing |

### Authentication Methods

```http
Authorization: Bearer <token>
```

Token can be:
- **API Key** (uF/pB/sF/tB prefix)
- **JWT** (Bearer token with JWT)
- **Session Token** (X-Session-Token header)

---

## API Endpoints

### Public Endpoints (No Auth Required)

#### POST /v1/auth/signup
Create new tenant account.

```http
POST /v1/auth/signup
Content-Type: application/json

{
  "email": "admin@company.com",
  "password": "securepassword",
  "tenantName": "Company Inc"
}
```

#### POST /v1/auth/login
Authenticate and receive tokens.

```http
POST /v1/auth/login
Content-Type: application/json

{
  "email": "admin@company.com",
  "password": "securepassword"
}
```

**Response:**
```json
{
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "expiresIn": 3600
}
```

#### POST /v1/auth/refresh
Refresh access token.

```http
POST /v1/auth/refresh
Authorization: Bearer <refresh_token>

{
  "token": "<refresh_token>"
}
```

---

### Authenticated Endpoints (Tenant-Scoped)

**All authenticated endpoints derive tenant from the credential - NO X-Tenant-ID header needed.**

#### GET /v1/users/me
Get current user profile.

```http
GET /v1/users/me
Authorization: Bearer <api_key_or_jwt>
```

**Response:**
```json
{
  "data": {
    "id": "user_abc123",
    "email": "admin@company.com",
    "createdAt": "2025-01-15T10:30:00Z"
  }
}
```

#### PATCH /v1/users/me
Update current user profile.

```http
PATCH /v1/users/me
Authorization: Bearer <api_key_or_jwt>
Content-Type: application/json

{
  "displayName": "John Doe"
}
```

#### GET /v1/users/me/identities
List linked identities.

```http
GET /v1/users/me/identities
Authorization: Bearer <api_key_or_jwt>
```

#### GET /v1/users/me/sessions
List active sessions.

```http
GET /v1/users/me/sessions?limit=20
Authorization: Bearer <api_key_or_jwt>
```

#### DELETE /v1/users/me/sessions/:id
Revoke a session.

```http
DELETE /v1/users/me/sessions/sess_abc123
Authorization: Bearer <api_key_or_jwt>
```

#### GET /v1/users/me/devices
List trusted devices.

```http
GET /v1/users/me/devices
Authorization: Bearer <api_key_or_jwt>
```

---

### Dynamic Modules API

#### GET /v1/modules/:moduleKey/resources/:resourceKey
Get module resource.

```http
GET /v1/modules/payments/resources/invoices
Authorization: Bearer <api_key>
```

#### POST /v1/modules/:moduleKey/commands/:commandKey
Execute module command.

```http
POST /v1/modules/payments/commands/create-invoice
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "amount": 1000,
  "currency": "USD",
  "customerId": "cus_abc123"
}
```

---

### API Key Management

#### POST /v1/api-keys
Create new API key pair.

```http
POST /v1/api-keys
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "name": "Production API Key",
  "scopes": ["read", "write"],
  "ipAllowlist": ["192.168.1.0/24"]
}
```

**Response:**
```json
{
  "publishableKey": "uF01ARZ3NDEKTSV4RRFFQ69G5FAVxl",
  "secretKey": "sF01ARZ3NDEKTSV4RRFFQ69G5FAVxl...",
  "key": { ... }
}
```

**⚠️ Secret key shown only once - store securely!**

#### GET /v1/api-keys
List API keys.

```http
GET /v1/api-keys
Authorization: Bearer <api_key>
```

#### DELETE /v1/api-keys/:id
Revoke API key.

```http
DELETE /v1/api-keys/key_abc123
Authorization: Bearer <api_key>
```

---

### Governance APIs

#### POST /v1/policies
Create policy.

```http
POST /v1/policies
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "name": "Require MFA",
  "rules": { ... },
  "description": "Enforce MFA for sensitive operations"
}
```

#### GET /v1/policies
List policies.

```http
GET /v1/policies
Authorization: Bearer <api_key>
```

---

## Platform APIs (Admin)

Platform APIs require `PlatformApiKeyGuard` with platform scopes.

### Impersonation

#### POST /platform/v1/impersonate/sessions
Start impersonation session.

```http
POST /platform/v1/impersonate/sessions
X-Platform-Key: pk_platform_xxx
Content-Type: application/json

{
  "platformIdentityId": "admin_123",
  "tenantId": "tenant_abc",
  "targetIdentityId": "user_xyz",
  "reason": "Debug payment issue"
}
```

---

## Error Responses

```json
{
  "error": {
    "code": "INVALID_API_KEY",
    "message": "API key validation failed"
  }
}
```

### Common Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| MISSING_AUTH | 401 | No authentication provided |
| INVALID_API_KEY | 401 | Invalid API key format |
| KEY_EXPIRED | 401 | API key has expired |
| KEY_INACTIVE | 403 | API key is revoked/suspended |
| IP_NOT_ALLOWED | 403 | IP not in allowlist |
| QUOTA_EXHAUSTED | 429 | Monthly quota exceeded |
| RATE_LIMITED | 429 | Too many requests |

---

## Rate Limits

| Tier | Limit | Window |
|------|-------|--------|
| Publishable Key | 1000/min | Per key |
| Secret Key | 5000/min | Per key |
| JWT | 1000/min | Per user |
| Platform Key | 10000/min | Per key |

---

## SDK Initialization

### Frontend (JavaScript)

```javascript
import { UICPClient } from '@uICP/sdk'

const client = new UICPClient({
  publishableKey: 'uF01ARZ3NDEKTSV4RRFFQ69G5FAVxl'
})

// Auth operations
await client.auth.signUp({ email, password })
await client.auth.signIn({ email, password })

// User operations
const user = await client.users.me()
```

### Backend (Node.js)

```javascript
import { UICP } from '@uICP/sdk'

const uicp = new UICP({
  secretKey: 'sF01ARZ3NDEKTSV4RRFFQ69G5FAVxl...'
})

// Server-side operations
const user = await uicp.users.get('user_abc123')
await uicp.apiKeys.create({ name: 'My Key' })
```

---

## Versioning

- Current: `v1`
- URL prefix: `/v1/`

---

## Security Best Practices

1. **Never expose secret keys** in frontend code
2. **Use publishable keys** for client-side operations
3. **Rotate keys regularly** - recommended every 90 days
4. **Use IP allowlists** for sensitive keys
5. **Monitor key usage** via `/v1/api-keys` analytics
6. **Revoke compromised keys immediately**

---

## Tenant Resolution (Internal)

```
Request → UnifiedAuthGuard
           ↓
    Validate credential (API Key / JWT / Session)
           ↓
    Extract tenantId from credential
           ↓
    Set req.tenantId, req.apiKey
           ↓
    Controller accesses via getTenantIdOrThrow(req)
```

**No X-Tenant-ID header required** - tenant is derived from the authenticated credential, matching Auth0/Clerk/Firebase patterns.
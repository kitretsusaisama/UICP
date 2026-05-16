# Authentication Overview

## Metadata
```yaml
title: Authentication Overview
domain: authentication
criticality: CRITICAL
security-impact: CRITICAL
ai-ingestable: true
```

---

## Authentication Methods

UICP supports multiple authentication methods through a unified auth service.

### Unified Auth Attempt (`/v1/auth/attempt`)

| Method | Value | Secret Required | Use Case |
|--------|-------|-----------------|----------|
| Password | `password` | Yes | Email/password login |
| OTP | `otp` | Yes (code) | MFA, verification |
| Magic Link | `magic_link` | No | Passwordless email |
| OAuth | `oauth` | No | External providers |

### Credential-Based (Bearer Token)

| Method | Header | Format | Validation |
|--------|--------|--------|------------|
| JWT | `Authorization: Bearer <token>` | RS256 | Signature + claims |
| API Key | `Authorization: Bearer uF...` | ULID | HMAC signature |
| API Key (Alt) | `X-API-Key: <key>` | ULID | HMAC signature |
| Internal Service | `X-Internal-Service-Token: <token>` | Plain | Exact match |
| Session | `X-Session-Token: <token>` | UUID | Redis lookup |

---

## Authentication Flow

### Password Authentication

```
1. Client sends credentials to /v1/auth/attempt
   { identity: "user@example.com", authMethod: "password", secret: "..." }

2. UnifiedAuthService validates credentials against credential repository

3. On success:
   - Generate JWT access token (15 min)
   - Generate JWT refresh token (7 days)
   - Create Redis session
   - Return { accessToken, refreshToken, principal, membership, actor }

4. On failure:
   - Return 401 Unauthorized
   - Log attempt for anomaly detection
```

### OTP Authentication

```
1. Client requests OTP via /v1/auth/otp/send
   { userId, purpose, recipient, channel }

2. OTP Service generates 6-digit code
   - TTL: 300 seconds (5 min)
   - Rate limit: 3 attempts per code

3. Client submits code via /v1/auth/attempt
   { identity: "+1234567890", authMethod: "otp", secret: "123456" }

4. OTP Service validates code, marks as used
```

---

## Session Management

### Session Lifecycle

```
Creation:
- Generate UUID session ID
- Store in Redis with 24-hour TTL
- Include tenantId, userId, device info
- Return session cookie/token

Validation:
- Lookup session in Redis
- Verify not expired
- Check tenant matches request
- Update last accessed timestamp

Termination:
- Logout: DELETE session from Redis
- Expiration: Redis auto-purge after TTL
- Force logout: Admin revocation
```

### Session Security

| Control | Implementation |
|---------|----------------|
| Storage | Redis with TLS |
| TTL | 24 hours (configurable) |
| Rotation | New token on refresh |
| Invalidation | Password change = all sessions terminated |
| Device Tracking | Fingerprint stored, anomaly alerts |

---

## Token Model

### Access Token (JWT)

```json
{
  "sub": "user-uuid",
  "tid": "tenant-uuid",
  "iat": 1700000000,
  "exp": 1700000900,
  "scopes": ["read", "write"],
  "roles": ["user"]
}
```

**Claims**:
- `sub`: User ID
- `tid`: Tenant ID (critical for tenant isolation)
- `exp`: Expiration (15 minutes)
- `scopes`: API permissions
- `roles`: Assigned roles

### Refresh Token

- Longer lifespan: 7 days
- Rotates on every use (old token invalidated)
- Used to obtain new access tokens

---

## Security Controls

| Control | Status |
|---------|--------|
| HMAC validation (API keys) | ✅ |
| RS256 JWT validation | ✅ |
| Rate limiting (per key) | ✅ |
| Account lockout | ✅ |
| Anomaly detection | ✅ |
| MFA support | ✅ |
| Session encryption | ✅ |
| Audit logging | ✅ |

---

## Related Documents

- `03-auth/login-flow.md`
- `03-auth/otp-flow.md`
- `03-auth/session-management.md`
- `03-auth/token-model.md`
- `05-security/zero-trust-model.md`


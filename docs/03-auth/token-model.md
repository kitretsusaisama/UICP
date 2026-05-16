# Token Model

## Metadata
```yaml
title: Authentication Token Model
domain: authentication
owner: identity-team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: LOW
provider-impact: LOW
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - session-management.md
  - refresh-rotation.md
related-docs:
  - jwt-claims.md
  - api-key-authentication.md
  - auth-security.md
related-queues:
  - token-events
related-services:
  - TokenService
  - JwtService
  - RedisCacheAdapter
related-runtime-states:
  - TOKEN_VALID
  - TOKEN_EXPIRED
  - TOKEN_REVOKED
```

---

## Token Types

UICP issues three primary token types:

| Type | Format | Use Case | Lifetime |
|------|--------|----------|----------|
| Access Token | JWT (RS256) | API authorization | 15 minutes |
| Refresh Token | JWT (RS256) | Token renewal | 7 days |
| Session Token | UUID | Session tracking | 24 hours |

---

## Access Token Structure

Access tokens are JSON Web Tokens signed with RS256 (RSA 2048-bit key). The token contains authorization claims but no sensitive user data.

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-id-2024"
  },
  "payload": {
    "sub": "ulid-user-abc123",
    "tid": "ulid-tenant-xyz789",
    "iat": 1700000000,
    "exp": 1700000900,
    "jti": "ulid-token-def456",
    "scopes": ["read", "write", "admin"],
    "roles": ["member", "admin"],
    "permissions": ["resource:read", "resource:write"]
  }
}
```

### Access Token Claims

| Claim | Type | Description |
|-------|------|-------------|
| sub | string | User ID (ULID) |
| tid | string | Tenant ID (ULID) |
| iat | integer | Issued at (Unix timestamp) |
| exp | integer | Expiration (Unix timestamp) |
| jti | string | JWT ID (ULID) |
| scopes | array | Authorized scopes |
| roles | array | Assigned roles |
| permissions | array | Explicit permissions |

---

## Refresh Token Structure

Refresh tokens follow similar structure to access tokens but include additional rotation metadata:

```json
{
  "sub": "ulid-user-abc123",
  "tid": "ulid-tenant-xyz789",
  "iat": 1700000000,
  "exp": 1700864000,
  "jti": "ulid-refresh-789xyz",
  "rti": "ulid-refresh-token", // Rotation token ID
  "scopes": ["refresh"]
}
```

### Refresh Token Claims

| Claim | Type | Description |
|-------|------|-------------|
| rti | string | Refresh token identifier for rotation |
| scopes | array | Always includes "refresh" |

---

## API Key Token Model

API keys use a different model based on HMAC-SHA256 signature rather than JWT:

```
API Key Format: ukey_<ULID>_<ULID>
Signature: HMAC-SHA256(keyMaterial, timestamp + method + path)
```

See `api-key-authentication.md` for complete API key documentation.

---

## Token Storage

### Memory (JWT)

JWTs are self-contained and validated cryptographically. No server-side storage required. The validation layer verifies signature and claims without database lookup.

### State (Refresh Tokens)

Refresh tokens validate against Redis to support rotation and revocation. The token store maps `jti` to session metadata.

```typescript
interface RefreshTokenStore {
  jti: string;
  userId: string;
  tenantId: string;
  issuedAt: Date;
  expiresAt: Date;
  rotated: boolean;
  deviceFingerprint: string;
}
```

---

## Token Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                        TOKEN LIFECYCLE                           │
├─────────────────────────────────────────────────────────────────┤
│  Issue (login) ──► Validate (API calls) ──► Refresh ──► Issue  │
│       │                  │                      │              │
│       ▼                  ▼                      ▼              │
│   15 minutes       15 minutes            7 days                │
│                                                                  │
│   Expiry ──► Re-authenticate                                     │
│   Revocation ──► Immediate rejection                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Related Documents

- `jwt-claims.md` - Detailed claim documentation
- `refresh-rotation.md` - Token refresh mechanics
- `auth-security.md` - Security controls
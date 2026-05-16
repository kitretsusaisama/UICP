# JWT Claims

## Metadata
```yaml
title: JWT Claims Reference
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
  - token-model.md
  - session-management.md
related-docs:
  - org-model.md
  - auth-security.md
  - auth-edge-cases.md
related-queues: []
related-services:
  - JwtService
  - TokenService
related-runtime-states:
  - TOKEN_VALIDATED
  - TOKEN_MALFORMED
  - CLAIMS_INVALID
```

---

## Standard Claims

### Subject (sub)

The `sub` claim identifies the principal. Format is ULID for consistent identifier length and sortability.

```
Valid: "ulid-01ar6qvwk2tjych5q6m2a"
Invalid: "user-123", "email@example.com"
```

### Tenant ID (tid)

The `tid` claim provides tenant isolation. Every token must include the tenant ID matching the resource being accessed. Tokens with mismatched tenant claims reject at the API gateway.

```json
{
  "sub": "ulid-user-123",
  "tid": "ulid-tenant-456"
}
```

### Expiration (exp)

The `exp` claim uses Unix timestamp (seconds since epoch). Access tokens expire in 15 minutes (900 seconds). Refresh tokens expire in 7 days (604800 seconds).

```
Access: exp = iat + 900
Refresh: exp = iat + 604800
```

### Issued At (iat)

The `iat` claim records token issuance time. Used for replay detection and token age validation. Tokens with future `iat` (clock skew > 60 seconds) reject.

---

## Custom Claims

### JWT ID (jti)

Unique identifier for each token instance. Enables token tracking for revocation and audit. Format: ULID.

```typescript
interface JtiPayload {
  jti: string; // ULID
  type: 'access' | 'refresh' | 'session';
}
```

### Scopes (scopes)

Array of authorized scope strings. Scopes define granular permissions for API access.

```
Common scopes: ["read", "write", "admin", "delete", "execute"]
Resource scopes: ["document:read", "document:write", "document:delete"]
```

### Roles (roles)

Assigned role identifiers. Roles map to permission sets defined in ABAC policies.

```
Standard roles: ["member", "moderator", "admin", "owner"]
Tenant roles: ["tenant-member", "tenant-admin"]
```

### Permissions (permissions)

Explicit permission list granted to the token. Permissions are computed from roles and direct grants at token issuance time.

```json
{
  "permissions": [
    "api:users:read",
    "api:users:write",
    "api:documents:read",
    "api:documents:write"
  ]
}
```

---

## Actor Claims

For impersonation and service-to-service calls, actor claims identify the acting entity:

```json
{
  "sub": "ulid-user-123",
  "actor": {
    "actorId": "ulid-admin-456",
    "actorType": "user",
    "impersonating": true
  }
}
```

### Actor Structure

| Field | Type | Description |
|-------|------|-------------|
| actorId | string | ULID of acting entity |
| actorType | string | "user", "service", "system" |
| impersonating | boolean | True if acting on behalf of another |

---

## Claims Validation Rules

### Required Claims

All tokens must include: `sub`, `tid`, `exp`, `iat`, `jti`

### Tenant Isolation

The `tid` claim must match the requested resource's tenant. Cross-tenant requests reject regardless of valid signature.

### Expiration

Tokens with `exp` in the past reject immediately. No leeway for expired tokens (use clock skew only for future `iat`).

### Scope Matching

API endpoints declare required scopes in their route configuration. Token scopes must contain all required scopes for access.

---

## Related Documents

- `token-model.md` - Token structure
- `org-model.md` - Role and permission model
- `auth-security.md` - Security controls
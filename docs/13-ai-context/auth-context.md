# Auth Context - AI Context

## Metadata
```yaml
title: Auth Context
domain: ai-context
owner: Identity Team
criticality: CRITICAL
runtime-impact: CRITICAL
security-impact: CRITICAL
queue-impact: LOW
provider-impact: LOW
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - security-rules.md
related-docs:
  - 04-identity/auth-flows.md
  - 05-api-keys/key-rotation.md
related-queues: []
related-services:
  - identity-service
  - token-service
  - session-manager
related-runtime-states:
  - authenticated
  - unauthenticated
  - expired
```

---

## Authentication Methods

### Priority 1: API Key
- Format: `uF{ULID26}xl` (public) or `sF{ULID26}xl{HMAC44}` (secret)
- Validation: ULID format + HMAC signature (secret keys)
- Tenant Extraction: Derived from key prefix
- Rate Limit: 1000/min per key

### Priority 2: JWT
- Algorithm: RS256
- Claims: `tid` (tenant_id), `sub` (user_id), `exp`, `iat`
- Lifespan: 900s access, 7-day refresh
- Validation: Signature + expiry + tenant claim

### Priority 3: Session Token
- Storage: Redis with tenant prefix
- Lifespan: 24 hours
- Validation: Redis lookup + expiry check

---

## Auth Flow Contracts

```
1. Client sends API Key / JWT / Session
2. API Gateway extracts credentials
3. Gateway validates (Redis for session, MySQL for key)
4. Gateway extracts tenant_id from credential
5. Gateway injects tenant context into request
6. Service processes with tenant context
7. Response returns without tenant in body
```

**Rule**: Tenant ID NEVER in response body for authenticated endpoints.

---

## Token Lifecycle

| Token Type | Created | Refreshed | Invalidated |
|------------|---------|-----------|-------------|
| Access Token | Login | Auto at 80% TTL | Password change, logout |
| Refresh Token | Login | Use | Password change, revoke |
| Session | Login | Activity | Logout, expiry, password change |
| API Key | Admin create | N/A | Revoke, expiry |

---

## Security Constraints

1. **HMAC Required**: All secret keys (`sF`/`tB`) must validate HMAC
2. **Tenant Isolation**: Sessions stored with tenant prefix
3. **Token Rotation**: Refresh tokens rotate on every use
4. **Emergency Revocation**: Redis purge for immediate invalidation

---

## Auth Failures

| Failure | Impact | Recovery |
|---------|--------|----------|
| Invalid API Key | 401 Unauthorized | Re-authenticate |
| Expired JWT | 401 Unauthorized | Use refresh token |
| Invalid Session | 401 Unauthorized | Re-login |
| HMAC Fail | 401 Unauthorized | Regenerate key |

---

## Related Context Files

- `system-summary.md` - Auth model summary
- `replay-model.md` - Replay protection
- `security-rules.md` - Security constraints

---

*AI-Ingestible: true | Authentication context for AI reasoning*
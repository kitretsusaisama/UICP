# Session Management

## Metadata
```yaml
title: Session Management
domain: authentication
owner: identity-team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - token-model.md
  - refresh-rotation.md
related-docs:
  - device-trust.md
  - session-management.md
  - auth-security.md
related-queues:
  - session-events
  - auth-analytics
related-services:
  - SessionService
  - RedisCacheAdapter
  - UnifiedAuthService
related-runtime-states:
  - SESSION_ACTIVE
  - SESSION_EXPIRED
  - SESSION_REVOKED
```

---

## Session Lifecycle

### Session Creation

Sessions are created upon successful authentication through the `SessionService.create()` method. Each session receives a UUID identifier stored in Redis with a configurable TTL (default: 24 hours). The session object contains tenant isolation data preventing cross-tenant access.

```
Session Creation Flow:
1. Authentication successful via UnifiedAuthService
2. Generate UUID session ID
3. Store in Redis: key = session:{id}, value = session object
4. Set TTL = 86400 seconds (24 hours)
5. Return session token to client
```

### Session Validation

Every authenticated request validates the session via `SessionService.validate()`. The validation process checks expiration, tenant matching, and device trust status. Valid sessions update their last-accessed timestamp to prevent premature expiration during active use.

```typescript
async function validateSession(sessionId: string, tenantId: string): Promise<Session> {
  const session = await this.redis.get(`session:${sessionId}`);

  if (!session) {
    throw new SessionNotFoundError();
  }

  if (session.tenantId !== tenantId) {
    throw new TenantMismatchError();
  }

  if (session.expiresAt < Date.now()) {
    throw new SessionExpiredError();
  }

  // Update last accessed
  await this.redis.expire(`session:${sessionId}`, 86400);

  return session;
}
```

### Session Termination

Sessions terminate through three mechanisms:

- **Logout**: Explicit client request deletes session from Redis immediately
- **Expiration**: Redis TTL auto-purges expired sessions
- **Revocation**: Admin or security systems force-terminate specific sessions

---

## Session Security Controls

### Storage Security

Session data encrypts at rest using AES-256-GCM. The encryption key derives from the KMS-managed master key. All Redis connections use TLS 1.3 transport encryption.

### Session Binding

Sessions bind to device fingerprint and IP address during creation. Subsequent requests validate these bindings; mismatches trigger re-authentication or security alert depending on configured strictness.

| Binding Type | Validation | Action on Mismatch |
|--------------|------------|-------------------|
| Device Fingerprint | Exact match | Re-authenticate |
| IP Address | Subnet match (/24) | Alert + log |
| User Agent | Substring match | Alert only |

### Concurrent Session Limits

The `MaxConcurrentSessions` setting (default: 5) limits active sessions per user. When exceeded, the oldest sessions automatically terminate. Administrators can configure per-user or per-tenant overrides.

---

## Session Persistence Across Authentication Methods

### Password Authentication

Creates new session with full permissions. Password change invalidates all existing sessions for the user.

### OAuth Authentication

Creates session linked to identity provider. OAuth token refresh extends session lifetime automatically.

### API Key Authentication

Does not create user sessions. API keys validate independently with their own rate limits and permissions.

### OTP Verification

Creates temporary session valid only for verification flow. Automatically expires after verification completes or after 5 minutes.

---

## Session Monitoring

### Active Session Queries

Users retrieve their active sessions via `GET /v1/auth/sessions`. The endpoint returns session metadata (device, IP, created time, last accessed) without exposing session IDs. Users can terminate individual sessions through the same API.

### Admin Session Management

Administrators view all user sessions through the audit service. Force-logout capability terminates sessions across all devices. Session history retained for 90 days for forensic analysis.

---

## Related Documents

- `token-model.md` - Token structure and claims
- `refresh-rotation.md` - Token refresh mechanics
- `device-trust.md` - Device binding implementation
- `auth-security.md` - Security controls overview
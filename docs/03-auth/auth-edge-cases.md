# Authentication Edge Cases

## Metadata
```yaml
title: Authentication Edge Cases
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
  - login-flow.md
  - token-model.md
  - session-management.md
related-docs:
  - auth-security.md
  - suspicious-login-detection.md
  - auth-failure-recovery.md
related-queues:
  - auth-errors
  - security-alerts
related-services:
  - UnifiedAuthService
  - TokenService
  - SessionService
related-runtime-states:
  - AUTHENTICATION_FAILED
  - TOKEN_EXPIRED
  - SESSION_INVALIDATED
```

---

## Concurrent Session Handling

### Multiple Device Login

When a user authenticates from a new device while existing sessions remain active, the system tracks both sessions independently. Each session receives a unique session ID stored in Redis with device fingerprint metadata. The `ConcurrentSessionLimit` configuration (default: 5 per user) triggers enforcement actions when exceeded.

```typescript
// Session creation with device tracking
const session = await sessionService.create({
  userId: user.id,
  deviceFingerprint: device.fingerprint,
  ipAddress: request.ip,
  userAgent: request.headers['user-agent'],
  tenantId: user.tenantId
});

if (await sessionService.countActiveSessions(user.id) > maxSessions) {
  // Optionally terminate oldest sessions or reject new login
  await sessionService.terminateOldestSessions(user.id, maxSessions);
}
```

### Session Fixation After Password Change

Password changes trigger automatic session invalidation across all devices. The `InvalidateSessionsOnPasswordChange` handler queries Redis for all session keys matching the user ID prefix and deletes them atomically. This prevents session hijacking via stolen session tokens after credential compromise.

---

## Token Edge Cases

### Expired Refresh Token With Active Access Token

An access token with 15-minute lifetime may outlive its parent refresh token if the refresh token expired during use. The API gateway validates access tokens first; on 401 response, the client should attempt refresh. If refresh fails with `TOKEN_EXPIRED`, the client must re-authenticate completely.

```json
{
  "error": "invalid_token",
  "error_description": "Refresh token has expired",
  "error_code": "REFRESH_TOKEN_EXPIRED"
}
```

### Token Claims Mismatch After Tenant Migration

Users migrating between tenants retain their user ID but receive a new tenant claim (`tid`). The validation layer enforces `tid` consistency: tokens with mismatched tenant claims are rejected regardless of valid signature. This prevents cross-tenant privilege escalation.

### Malformed JWT Handling

JWTs with invalid JSON structure, missing required claims (`sub`, `tid`, `exp`), or invalid signature formats trigger `MALFORMED_TOKEN` errors. The parser logs sanitized error details (claim names, not values) for debugging while returning generic error to client.

---

## Authentication Method Transitions

### Password to OTP Migration

Users enabling MFA transition from password-only to OTP-required flow. During the transition period, the system accepts both authentication methods but logs the method used. Once MFA is fully enforced, password attempts return `MFA_REQUIRED` and prompt OTP submission.

### OAuth to Local Account Linking

OAuth authentication may link to existing local account via email matching. If local account has different password, the system preserves both authentication paths. The `LinkOAuthAccount` handler merges identity providers while maintaining separate credential stores.

---

## Clock Skew Tolerance

System clocks may drift between client and server, causing premature token expiration detection. The JWT validation includes 60-second clock skew tolerance (`leeway`) in expiration checks. Tokens appearing expired by up to 60 seconds due to clock difference are still accepted.

---

## Related Documents

- `auth-security.md` - Security controls and threat mitigation
- `auth-failure-recovery.md` - Error handling patterns
- `suspicious-login-detection.md` - Anomaly detection during edge cases
# Authentication Failure Recovery

## Metadata
```yaml
title: Authentication Failure Recovery
domain: authentication
owner: identity-team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: LOW
provider-impact: MEDIUM
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - login-flow.md
  - auth-security.md
related-docs:
  - auth-edge-cases.md
  - auth-rate-limits.md
  - password-reset-flow.md
related-queues:
  - auth-errors
  - recovery-events
related-services:
  - UnifiedAuthService
  - RecoveryService
  - SupportService
related-runtime-states:
  - AUTH_FAILED
  - AUTH_RECOVERED
  - RECOVERY_IN_PROGRESS
```

---

## Failure Scenarios

### Token Expiration

Access tokens expire after 15 minutes. On 401 response, clients should use refresh token to obtain new access token. If refresh fails, client must re-authenticate.

```json
{
  "error": "token_expired",
  "error_description": "Access token has expired",
  "refreshable": true
}
```

### Token Revocation

Tokens may revoke due to logout, password change, or security event. Revoked tokens return 401 with specific error:

```json
{
  "error": "token_revoked",
  "error_description": "Token has been revoked",
  "reason": "password_changed"
}
```

### Session Expiry

Sessions expire after 24 hours of inactivity. On session expiry, clients must re-authenticate completely (not just refresh token).

---

## Recovery Procedures

### Automatic Recovery

For transient failures, the system implements automatic retry with exponential backoff:

```
1. Initial request fails (timeout, temporary error)
2. Wait 1 second, retry
3. Wait 2 seconds, retry
4. Wait 4 seconds, retry
5. Fail after 3 attempts, return error
```

### Token Refresh Failure

When refresh token fails, the client should clear stored credentials and prompt re-authentication:

```typescript
async function handleRefreshFailure(error: AuthError): Promise<void> {
  if (error.code === 'REFRESH_TOKEN_EXPIRED' ||
      error.code === 'REFRESH_TOKEN_REVOKED') {
    await this.authStorage.clearTokens();
    await this.navigateToLogin();
  }
}
```

### Manual Recovery

For account lockout or recovery issues, users can:

- Wait for lockout expiry (30 minutes default)
- Use password reset to regain access
- Contact support with identity verification

---

## Error Codes

| Code | Description | Recovery Action |
|------|-------------|-----------------|
| INVALID_CREDENTIALS | Wrong password/email | Re-enter credentials |
| ACCOUNT_LOCKED | Too many failed attempts | Wait or reset password |
| ACCOUNT_DISABLED | Admin disabled account | Contact support |
| MFA_REQUIRED | MFA challenge pending | Complete MFA |
| TOKEN_EXPIRED | Token lifespan ended | Refresh or re-auth |
| TOKEN_REVOKED | Security event revoked | Re-authenticate |
| SESSION_EXPIRED | Session ended | Re-login |
| TENANT_SUSPENDED | Tenant not active | Contact tenant admin |

---

## Support Integration

### Recovery Requests

Users unable to recover through automated means submit support requests. Identity verification required before account access grants.

### Administrative Recovery

Tenant admins can force-logout users, unlock accounts, and reset MFA for users within their tenant.

---

## Related Documents

- `login-flow.md` - Login process
- `password-reset-flow.md` - Password recovery
- `auth-edge-cases.md` - Edge case handling
# Replay Prevention

## Metadata
```yaml
title: Replay Attack Prevention
domain: authentication
owner: security-team
criticality: CRITICAL
runtime-impact: MEDIUM
security-impact: CRITICAL
queue-impact: LOW
provider-impact: LOW
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - token-model.md
  - jwt-claims.md
  - auth-security.md
related-docs:
  - auth-edge-cases.md
  - auth-rate-limits.md
related-queues:
  - security-events
  - auth-analytics
related-services:
  - TokenService
  - UnifiedAuthService
  - RedisCacheAdapter
related-runtime-states:
  - TOKEN_VALIDATED
  - REPLAY_DETECTED
related-threat-models:
  - TOKEN_REPLAY
  - OAUTH_STATE_INJECTION
```

---

## Token Replay Prevention

### Nonce-Based Protection

Refresh tokens include a cryptographic nonce generated during issuance. The token store maintains a nonce-to-session mapping in Redis with the refresh token's expiration TTL. When a token is used for refresh, the nonce is validated and then invalidated immediately, preventing reuse.

```typescript
// Token refresh with nonce validation
async function refreshToken(refreshToken: string): Promise<TokenPair> {
  const tokenData = await this.tokenStore.get(refreshToken);

  if (!tokenData) {
    throw new Error('TOKEN_INVALID');
  }

  if (tokenData.used) {
    // Replay attack detected - invalidate entire session
    await this.sessionService.invalidateUserSessions(tokenData.userId);
    throw new Error('REPLAY_ATTACK_DETECTED');
  }

  // Mark token as used
  await this.tokenStore.markUsed(refreshToken);

  // Issue new token pair with new nonce
  return this.issueNewTokenPair(tokenData.userId, tokenData.tenantId);
}
```

### Signed Token Introspection

For API keys, the signature includes a request timestamp. The validation layer rejects requests with timestamps older than 300 seconds (5 minutes). This window balances usability against replay window exposure.

---

## Request Replay Prevention

### Idempotency Keys

State-changing operations (`POST`, `PUT`, `DELETE`) require an `X-Idempotency-Key` header with a UUID. The idempotency store (Redis) caches the request hash and response for 24 hours. Duplicate requests within the window return the cached response without re-execution.

```
Request Flow:
1. Client sends POST /api/resource with Idempotency-Key: abc-123
2. Server checks Redis for existing key
3. If exists: return cached response
4. If new: process request, cache result, return response
```

### CSRF Token Rotation

Form submissions include CSRF tokens validated against session state. Tokens rotate on every authenticated request to prevent session fixation through CSRF token theft. The `Secure`, `HttpOnly`, and `SameSite=Strict` cookies contain the token.

---

## OAuth State Parameter Validation

OAuth authorization requests include a cryptographically random `state` parameter stored in the user's session. During callback processing, the returned state is compared against the stored value. Mismatched state indicates potential cross-site request forgery or state injection attack.

```typescript
// OAuth callback state validation
async function handleOAuthCallback(code: string, state: string) {
  const session = await this.sessionService.get(request.sessionId);

  if (state !== session.oauthState) {
    await this.securityAlertService.notify('OAuth state mismatch', {
      expected: session.oauthState,
      received: state
    });
    throw new Error('INVALID_OAUTH_STATE');
  }

  // Proceed with token exchange
}
```

---

## Rate Limiting Impact on Replay

The rate limiter provides secondary replay protection by throttling repeated attempts. For token refresh endpoints, the limit is 10 requests per minute per session. Brute-force replay attacks require thousands of attempts, which the rate limiter blocks before reaching the validation layer.

---

## Related Documents

- `auth-security.md` - Security controls and threat models
- `auth-rate-limits.md` - Rate limiting configuration
- `auth-edge-cases.md` - Edge case handling
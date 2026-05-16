# Replay Model - AI Context

## Metadata
```yaml
title: Replay Model
domain: ai-context
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - auth-context.md
  - security-rules.md
related-docs:
  - 05-api-keys/replay-protection.md
  - 10-security/threat-mitigation.md
related-queues:
  - webhook-processing
related-services:
  - identity-service
  - token-service
related-runtime-states:
  - valid
  - expired
  - consumed
```

---

## Replay Protection Mechanisms

### 1. Token Replay Prevention

| Token Type | Lifespan | Rotation | Replay Window |
|------------|----------|----------|---------------|
| Access Token | 900s (15 min) | Auto at 80% | ~3 min |
| Refresh Token | 604800s (7 days) | On use | ~15 min |
| API Key | Until expiry | Manual | Infinite if not revoked |

**Rule**: Refresh tokens rotate on every use to prevent replay.

### 2. Session Replay Prevention

- Sessions invalidated on: logout, password change, admin revoke
- Session TTL: 86400s (24 hours)
- Activity extends TTL (sliding window)

### 3. API Request Replay Prevention

- Idempotency keys required on all mutations
- Keys stored in Redis with 24h TTL
- Duplicate submissions rejected

---

## Idempotency Contract

```
Request: POST /api/v1/otp/send
Header: Idempotency-Key: {ULID}
Cache: {key} → {response}
Response: 200 OK + cached response (if duplicate)
```

---

## Replay Attack Scenarios

| Attack Vector | Mitigation |
|---------------|------------|
| Stolen JWT | Short lifespan (15 min) |
| Stolen refresh token | Rotation on use |
| Stolen session | TTL + activity check |
| Stolen API key | HMAC validation, rate limit |
| Reused idempotency key | 24h TTL, reject duplicates |

---

## Emergency Response

| Scenario | Action |
|----------|--------|
| Token leak suspected | Invalidate all user tokens |
| API key compromised | Revoke key, purge Redis cache |
| Session hijack | Terminate session, force re-login |

---

## Related Context Files

- `auth-context.md` - Token lifecycle
- `security-rules.md` - Security constraints
- `lineage-model.md` - Request traceability

---

*AI-Ingestible: true | Replay protection context for AI*
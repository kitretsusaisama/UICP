# Authentication Rate Limits

## Metadata
```yaml
title: Authentication Rate Limits
domain: security
owner: security-team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: LOW
provider-impact: LOW
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - auth-security.md
  - replay-prevention.md
related-docs:
  - auth-edge-cases.md
  - auth-failure-recovery.md
  - suspicious-login-detection.md
related-queues:
  - rate-limit-events
  - security-alerts
related-services:
  - RateLimiter
  - RedisCacheAdapter
related-runtime-states:
  - RATE_LIMITED
  - RATE_LIMIT_EXCEEDED
```

---

## Rate Limit Configuration

### Endpoint Limits

Rate limits apply per authentication endpoint based on sensitivity:

| Endpoint | Limit | Window | Scope |
|----------|-------|--------|-------|
| POST /auth/attempt | 10 | 1 min | IP |
| POST /auth/signup | 5 | 1 hour | IP |
| POST /auth/otp/send | 3 | 1 min | User |
| POST /auth/password/reset/request | 5 | 1 hour | IP |
| POST /token/refresh | 10 | 1 min | Session |
| GET /auth/sessions | 30 | 1 min | User |

### Limit Scope

Rate limits scope to IP address, user ID, or session depending on endpoint. IP-based limits prevent mass attacks. User-based limits prevent per-account abuse.

---

## Rate Limit Implementation

### Token Bucket Algorithm

The rate limiter uses token bucket for smooth rate distribution:

```typescript
interface TokenBucket {
  capacity: number; // Max tokens
  tokens: number;   // Current tokens
  refillRate: number; // Tokens per second
  lastRefill: Date;
}
```

### Redis Storage

Rate limit counters store in Redis with expiry matching the window:

```
Key: rate_limit:{endpoint}:{scope}:{identifier}
Value: count
TTL: window duration
```

---

## Response Headers

Rate-limited responses include headers indicating current limit status:

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 3
X-RateLimit-Reset: 1700000000
Retry-After: 45
```

---

## Exceeded Limit Handling

### Soft Limit

When limit approaches (remaining < 2), responses include warning headers. Clients should reduce request frequency proactively.

### Hard Limit

When limit exceeded, requests return 429 Too Many Requests with JSON body:

```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many authentication attempts",
  "retryAfter": 45
}
```

### Exponential Backoff

Clients should implement exponential backoff on 429 responses:

```
Attempt 1: wait 1 second
Attempt 2: wait 2 seconds
Attempt 3: wait 4 seconds
Max backoff: 60 seconds
```

---

## Security Integration

### Attack Detection

Rate limit events correlate with security monitoring. High rate limit counts from single IP trigger security alerts.

### CAPTCHA Integration

Exceeded limits on signup and login may prompt CAPTCHA challenge for continued access.

---

## Related Documents

- `auth-security.md` - Security controls
- `auth-edge-cases.md` - Edge case handling
- `auth-failure-recovery.md` - Error handling
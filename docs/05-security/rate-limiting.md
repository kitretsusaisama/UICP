# Rate Limiting

## Metadata
```yaml
title: Rate Limiting
domain: security
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: LOW
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/zero-trust-model.md
  - 05-security/abuse-prevention.md
related-docs:
  - 02-runtime/cache-runtime.md
  - 05-security/threat-model.md
related-queues: []
related-services:
  - RateLimiter
  - TokenBucket
  - SlidingWindowCounter
related-runtime-states:
  - within-limit
  - rate-limited
  - quota-exceeded
```

---

## Executive Summary

Rate limiting protects UICP infrastructure from abuse and ensures fair resource allocation across tenants. It operates at multiple levels: per API key, per tenant, per endpoint, and per provider.

---

## Rate Limit Tiers

### Tier Definitions

| Tier | Requests/Min | Burst | Use Case |
|------|--------------|-------|----------|
| Free | 60 | 10 | Development |
| Starter | 600 | 100 | Small apps |
| Pro | 6,000 | 1,000 | Production |
| Enterprise | 60,000 | 10,000 | High volume |

---

## Rate Limit Strategy

### Token Bucket Algorithm

```
┌─────────────────────────────────────────────────────────────────┐
│                   TOKEN BUCKET MODEL                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────┐    add tokens     ┌─────────┐    consume     ┌─────┐│
│  │ bucket │◀─── at rate ───▶│ bucket  │◀─── on ──────▶│request││
│  │ state: │     (1/sec)       │ state:  │     request   │      ││
│  │ tokens │                   │ tokens  │               └──────┘│
│  │ last   │                   │ tokens  │                      │
│  │ refill │                   │ max=60  │                      │
│  └─────────┘                   └─────────┘                      │
│                                                                  │
│  If bucket.tokens >= 1:                                        │
│    - Allow request                                             │
│    - bucket.tokens -= 1                                        │
│  Else:                                                          │
│    - Reject with 429                                           │
│    - Return Retry-After header                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation

```typescript
class TokenBucketRateLimiter {
  private bucket: Map<string, TokenBucket> = new Map();

  async checkLimit(key: string, cost: number = 1): Promise<RateLimitResult> {
    const bucket = this.getOrCreateBucket(key);

    // Refill tokens based on elapsed time
    const now = Date.now();
    const elapsed = (now - bucket.lastRefill) / 1000;
    bucket.tokens = Math.min(
      bucket.maxTokens,
      bucket.tokens + elapsed * bucket.refillRate
    );
    bucket.lastRefill = now;

    // Check if sufficient tokens available
    if (bucket.tokens >= cost) {
      bucket.tokens -= cost;
      return {
        allowed: true,
        remaining: Math.floor(bucket.tokens),
        resetAt: bucket.lastRefill + (bucket.tokens / bucket.refillRate) * 1000
      };
    }

    return {
      allowed: false,
      remaining: 0,
      resetAt: bucket.lastRefill + ((bucket.maxTokens - bucket.tokens) / bucket.refillRate) * 1000
    };
  }
}
```

---

## Rate Limit Scope

### Per API Key

```
X-API-Key: uF01ARZ3NDEKTSV4RRFFQ69G5FAV

Rate limit: {tier}/minute
Key: rate-limit:api-key:01ARZ3NDEKTSV4RRFFQ69G5FAV
```

### Per Tenant

```
Rate limit: {tier}/minute aggregate across all keys
Key: rate-limit:tenant:tenant_abc
```

### Per Endpoint

```
Endpoint-specific limits:
- /v1/queues (POST): 100/min
- /v1/analytics: 30/min
- /v1/providers: 10/min
```

### Per Provider

```
Provider-specific rate limits:
- AWS SES: 10 emails/second
- Twilio: 100 SMS/minute
- Resend: 50 emails/minute
```

---

## Response Headers

```
X-RateLimit-Limit: 600
X-RateLimit-Remaining: 543
X-RateLimit-Reset: 1704067260
Retry-After: 12 (when 429)
```

---

## Handling Rate Limit Exceeded

```typescript
@Catch(RateLimitExceededError)
handleException(exception: RateLimitException, response: Response) {
  response.status(429).json({
    error: 'rate_limit_exceeded',
    message: 'Too many requests',
    retryAfter: exception.retryAfter,
    limit: exception.limit,
    remaining: exception.remaining
  });

  // Set retry-after header
  response.set('Retry-After', exception.retryAfter.toString());
}
```

---

## Failure Modes

| Mode | Impact | Mitigation |
|------|--------|------------|
| Redis down | Cannot track limits | Fail open, log heavily |
| Counter drift | Inaccurate limits | Periodic sync, audit |
| Burst traffic | Latency spike | Burst allowance per tier |
| Provider rate limit | Queue backup | Automatic backoff |

---

## Trust Boundaries

| Layer | Rate Limit | Implementation |
|-------|------------|----------------|
| API Gateway | Per API key | Token bucket |
| Application | Per tenant | Sliding window |
| Provider | Per provider | Token bucket |
| Queue | Per worker | Concurrency limit |

---

## Related Documents

- `05-security/zero-trust-model.md`
- `05-security/abuse-prevention.md`
- `02-runtime/cache-runtime.md`
# Rate Limits

## Metadata
```yaml
title: API Rate Limits
domain: api
owner: platform-team
criticality: HIGH
runtime-impact: medium
security-impact: MEDIUM
queue-impact: low
provider-impact: none
tenant-impact: isolated
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - authentication.md
related-docs:
  - errors.md
  - idempotency.md
related-queues: []
related-services:
  - RedisCacheAdapter
```

---

## Overview

API rate limits protect the platform from abuse and ensure fair resource allocation. Limits are applied per tenant and vary by endpoint category. Rate limit headers are included in all API responses.

---

## Rate Limit Headers

| Header | Description |
|--------|-------------|
| X-RateLimit-Limit | Maximum requests allowed in window |
| X-RateLimit-Remaining | Requests remaining in current window |
| X-RateLimit-Reset | Unix timestamp when the window resets |
| Retry-After | Seconds to wait before retry (only on 429) |

Example:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1715851200
```

---

## Default Limits

| Tier | Requests/Minute | Burst Limit |
|------|-----------------|--------------|
| Free | 60 | 100 |
| Starter | 300 | 500 |
| Professional | 1000 | 1500 |
| Enterprise | 5000 | 7500 |

---

## Endpoint Categories

### Authentication Endpoints

| Endpoint | Limit (per user) |
|----------|------------------|
| POST /login | 10/min |
| POST /register | 5/min |
| POST /refresh | 20/min |

### User Management

| Endpoint | Limit (per tenant) |
|----------|-------------------|
| GET /users | 30/min |
| POST /users | 10/min |
| PATCH /users/:id | 60/min |
| DELETE /users/:id | 20/min |

### Communication

| Endpoint | Limit (per tenant) |
|----------|-------------------|
| POST /communications/email | 100/min |
| POST /communications/sms | 50/min |
| POST /communications/push | 100/min |

### Platform Operations

| Endpoint | Limit (per tenant) |
|----------|-------------------|
| POST /platform/encrypt | 60/min |
| POST /platform/decrypt | 60/min |
| POST /platform/keys | 20/min |

---

## Rate Limit Calculation

Rate limits are calculated using a sliding window algorithm stored in Redis. The window slides continuously rather than resetting at fixed intervals, providing smoother rate limiting.

```
Available = Limit - (Requests in sliding window)
Window resets when RequestAge > WindowSize
```

---

## Handling Rate Limits

### On 429 Response

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded",
    "retryAfter": 45
  }
}
```

Wait `retryAfter` seconds before retrying.

### Exponential Backoff

For 5xx errors and 429, use exponential backoff:

```
Attempt 1: wait 1 second
Attempt 2: wait 2 seconds
Attempt 3: wait 4 seconds
Attempt 4: wait 8 seconds
Attempt 5: wait 16 seconds (max)
```

### Best Practices

1. **Cache responses** when possible to reduce requests
2. **Batch operations** using bulk endpoints
3. **Implement client-side throttling** before limits are hit
4. **Use idempotency keys** for retryable operations
5. **Monitor rate limit headers** to track usage

---

## Burst Handling

Burst limits allow short-term excess traffic. When burst limit is exceeded, requests are queued and processed at the standard rate.

- Burst window: 10 seconds
- Burst allowance: 150% of standard limit

---

## Tier Upgrades

Rate limits can be increased by upgrading tier. Contact your account manager for custom limits.

**Request format:**
```json
{
  "desiredLimit": 10000,
  "useCase": "high-volume-integration",
  "expectedTraffic": "10000 req/min"
}
```

---

## Monitoring

Query current rate limit status:

**GET** `/api/v1/rate-limit/status`

**Response (200):**
```json
{
  "limit": 1000,
  "remaining": 750,
  "resetAt": "2026-05-16T10:01:00Z",
  "burstRemaining": 500
}
```
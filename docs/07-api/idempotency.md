# Idempotency

## Metadata
```yaml
title: API Idempotency
domain: api
owner: platform-team
criticality: HIGH
runtime-impact: low
security-impact: MEDIUM
queue-impact: medium
provider-impact: none
tenant-impact: isolated
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - rate-limits.md
related-docs:
  - rate-limits.md
  - replay-rules.md
related-queues:
  - idempotency-check
related-services:
  - IdempotencyService
  - RedisCacheAdapter
```

---

## Overview

Idempotency ensures that duplicate requests produce the same result regardless of how many times they are sent. This is critical for payment processing, order creation, and other operations where duplicate requests could cause data corruption or financial issues.

---

## Idempotency Keys

Clients must provide an idempotency key in the request header:

```
Idempotency-Key: <unique-value>
```

The key must:
- Be unique per client request
- Be no longer than 256 characters
- Contain only alphanumeric characters, dashes, and underscores
- Be retained for at least 24 hours

---

## Supported Endpoints

| Method | Endpoint | Idempotent |
|--------|----------|------------|
| POST | /users | Yes |
| POST | /orders | Yes |
| POST | /payments | Yes |
| POST | /communications/email | Yes |
| POST | /communications/sms | Yes |
| POST | /api-keys | Yes |
| DELETE | /users/:id | Yes |
| DELETE | /api-keys/:id | Yes |
| PATCH | /users/:id | Yes |
| PATCH | /orders/:id | Yes |

GET, LIST endpoints are inherently idempotent.

---

## Request Format

Include the idempotency key in the request header:

```http
POST /api/v1/orders HTTP/1.1
Authorization: Bearer eyJhbGci...
Idempotency-Key: order-create-20260516-001
Content-Type: application/json

{
  "items": [...],
  "total": 100.00
}
```

---

## Response Format

The first request returns the normal response:

```json
{
  "orderId": "ulid-string",
  "status": "created",
  "createdAt": "2026-05-16T10:00:00Z"
}
```

Subsequent requests with the same key return the cached response:

```json
{
  "orderId": "ulid-string",
  "status": "created",
  "createdAt": "2026-05-16T10:00:00Z",
  "idempotentReplay": true
}
```

---

## Idempotency Response Headers

| Header | Description |
|--------|-------------|
| Idempotency-Key | The key used for this request |
| Idempotency-Replayed | Set to "true" if response is cached |
| Idempotency-Created-At | When the original request was processed |

---

## Caching Behavior

- **Storage**: Idempotency keys are stored in Redis
- **TTL**: 24 hours (configurable per endpoint)
- **Key format**: `idempotency:{tenantId}:{key}`

Cached responses include:
- HTTP status code
- Response body
- All response headers
- Error responses are also cached

---

## Handling Duplicate Requests

### Same Idempotency Key, Different Payload

If the request body differs from the original, return 422:

```json
{
  "error": {
    "code": "IDEMPOTENCY_KEY_MISMATCH",
    "message": "Request body differs from original request with same idempotency key",
    "originalRequestHash": "sha256-hash"
  }
}
```

### Expired Idempotency Key

If the key has expired, process as a new request:

```json
{
  "warning": {
    "code": "IDEMPOTENCY_KEY_EXPIRED",
    "message": "Original key expired. Processing as new request."
  }
}
```

### Concurrent Requests

The first request to complete wins. Subsequent concurrent requests wait up to 5 seconds for the result:

```json
{
  "error": {
    "code": "IDEMPOTENCY_CONFLICT",
    "message": "Request already in progress with this key"
  }
}
```

---

## Best Practices

1. **Use stable keys**: Generate keys from business identifiers (e.g., `order-{orderNumber}`)
2. **Include context**: Add timestamp or sequence number for unique requests
3. **Store keys**: Save idempotency keys in your database for retry handling
4. **Handle 409**: If you receive a conflict, wait and retry with same key
5. **Check replay flag**: Mark replayed responses in your application

---

## Example Implementation

```javascript
async function createOrder(orderData) {
  const idempotencyKey = `order-${orderData.orderNumber}-${Date.now()}`;

  const response = await fetch('/api/v1/orders', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Idempotency-Key': idempotencyKey,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(orderData)
  });

  if (response.status === 409) {
    // Wait and retry
    await delay(1000);
    return createOrder(orderData);
  }

  return response.json();
}
```

---

## Limits

- Maximum concurrent idempotent requests: 10
- Idempotency key length: 256 characters
- Cache duration: 24 hours (default)
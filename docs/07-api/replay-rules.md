# Replay Rules

## Metadata
```yaml
title: API Replay Rules
domain: api
owner: platform-team
criticality: HIGH
runtime-impact: medium
security-impact: MEDIUM
queue-impact: high
provider-impact: medium
tenant-impact: isolated
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - idempotency.md
  - rate-limits.md
related-docs:
  - idempotency.md
  - errors.md
related-queues:
  - replay-processing
  - outbox
related-services:
  - OutboxRepository
  - ReplayService
```

---

## Overview

Replay rules define how failed or interrupted operations can be safely retried. The system uses an outbox pattern to ensure reliable message delivery and provides configurable retry policies with exponential backoff.

---

## Outbox Pattern

The outbox pattern ensures that operations are reliably recorded before being processed. Every write operation creates an outbox entry that is later processed by a background worker.

### Flow

1. Client sends request to API
2. API writes to outbox table (transactional)
3. API returns response to client
4. Background worker processes outbox
5. Worker updates status and marks complete

---

## Retry Policies

### Default Retry Configuration

| Attempt | Delay | Max Total |
|---------|-------|-----------|
| 1 | 1 second | 1s |
| 2 | 2 seconds | 3s |
| 3 | 4 seconds | 7s |
| 4 | 8 seconds | 15s |
| 5 | 16 seconds | 31s |

After 5 attempts, the operation is moved to dead letter queue.

### Custom Retry Policy

```json
{
  "retryPolicy": {
    "maxAttempts": 10,
    "initialDelay": 500,
    "maxDelay": 30000,
    "multiplier": 2.0,
    "jitter": true
  }
}
```

---

## Operation Types

### Safe to Retry (Idempotent)

These operations can be safely retried:

- GET requests
- List operations
- Status checks
- DELETE operations (idempotent)
- PATCH operations with idempotency keys

### Conditional Retry

These operations require idempotency keys:

- POST /users
- POST /orders
- POST /payments
- POST /communications/*

### Do Not Retry

These operations should not be retried automatically:

- Authentication failures (401)
- Validation failures (422)
- Resource conflicts (409)
- Insufficient permissions (403)

---

## Dead Letter Queue

Operations that fail after all retries are moved to the dead letter queue (DLQ).

### DLQ Entry Format

```json
{
  "entryId": "ulid-string",
  "operation": "create-order",
  "payload": {...},
  "attempts": 5,
  "lastError": "Provider timeout",
  "failedAt": "2026-05-16T10:00:00Z",
  "tenantId": "ulid-string"
}
```

### Handling DLQ

**GET** `/api/v1/replay/dlq`

List dead letter entries.

**POST** `/api/v1/replay/dlq/{entryId}/retry`

Manually retry a DLQ entry.

**DELETE** `/api/v1/replay/dlq/{entryId}`

Remove entry from DLQ.

---

## Webhook Replay

Failed webhook deliveries can be automatically or manually replayed.

### Automatic Replay

```json
{
  "retryConfig": {
    "enabled": true,
    "maxRetries": 3,
    "retryInterval": 60000,
    "backoffMultiplier": 2.0
  }
}
```

### Manual Replay

**POST** `/api/v1/webhooks/{webhookId}/deliveries/{deliveryId}/retry`

---

## Message Replay

Event store messages can be replayed for rebuilding projections.

### Replay Events

**POST** `/api/v1/replay/events`

```json
{
  "streamId": "order-ulid",
  "fromPosition": 0,
  "toPosition": 100,
  "handlers": ["order-projection", "notification-handler"]
}
```

### Replay Status

**GET** `/api/v1/replay/{replayId}`

```json
{
  "replayId": "ulid-string",
  "status": "in_progress",
  "progress": {
    "processed": 500,
    "total": 1000,
    "percentage": 50
  }
}
```

---

## Best Practices

1. **Use idempotency keys** for all POST operations
2. **Implement exponential backoff** in client code
3. **Monitor dead letter queue** for systematic issues
4. **Set appropriate timeouts** for long-running operations
5. **Log all retry attempts** for debugging

---

## Circuit Breaker

Operations that repeatedly fail trigger the circuit breaker:

| State | Behavior |
|-------|----------|
| Closed | Normal operation |
| Open | Fail fast, return 503 |
| Half-Open | Allow test requests |

The circuit opens after 10 consecutive failures and resets after 30 seconds of success.

---

## Configuration

```yaml
replay:
  enabled: true
  defaultPolicy:
    maxAttempts: 5
    initialDelay: 1000
    maxDelay: 30000
    multiplier: 2.0
  circuitBreaker:
    failureThreshold: 10
    resetTimeout: 30000
  dlq:
    retentionDays: 30
    maxSize: 10000
```
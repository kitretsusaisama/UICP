# Queue-First Design

## Metadata
```yaml
title: Queue-First Design
domain: architecture
owner: Runtime Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: CRITICAL
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - event-driven-runtime.md
  - replay-safe-design.md
related-docs:
  - runtime-summary.md
  - orchestration-model.md
related-queues:
  - email-delivery
  - sms-delivery
  - webhook-processing
  - otp-fastlane
  - audit-logging
related-services:
  - queue-worker
  - provider-router
related-runtime-states:
  - running
  - degraded
  - recovering
related-threat-models:
  - queue-storm
  - provider-outage
```

---

## Overview

Queue-first design means all external operations (provider calls, webhooks, notifications) flow through message queues. This prevents cascading failures and ensures exactly-once delivery through idempotency.

---

## Queue Architecture

### BullMQ Integration

UICP uses BullMQ for queue management. Jobs are enqueued by API nodes and processed by worker nodes.

```
┌──────────────┐    enqueue    ┌──────────────┐    process    ┌──────────────┐
│  API Node    │ ──────────────→│    Queue     │ ──────────────→│    Worker    │
└──────────────┘               └──────────────┘               └──────────────┘
```

### Queue Configuration

| Queue | Priority | Workers | Retry Policy | DLQ |
|-------|----------|---------|--------------|-----|
| otp-fastlane | CRITICAL | 10 | 1x immediate | Yes |
| email-delivery | MEDIUM | 20 | 3x exponential | Yes |
| sms-delivery | HIGH | 15 | 3x exponential | Yes |
| webhook-processing | LOW | 5 | 5x linear | Yes |
| audit-logging | LOW | 3 | 3x exponential | Yes |

---

## Job Structure

### Standard Job Payload

```typescript
interface QueueJob {
  id: string;           // ULID
  name: string;         // Operation name
  data: JobData;        // Operation data
  opts: JobOptions;     // Queue options

  // Idempotency key (CRITICAL)
  idempotencyKey: string;

  // Tenant context
  tenantId: TenantId;
  userId?: UserId;

  // Retry configuration
  attempts: number;
  backoff: {
    type: 'exponential' | 'linear';
    delay: number;
  };

  // Timeout
  timeout: number;       // Max processing time
}
```

### Example: Email Job

```typescript
{
  id: '01ARZ3NDEKTSV4RRFFQ69G7FAK',
  name: 'send-email',
  data: {
    to: 'user@example.com',
    subject: 'Welcome',
    body: '...',
    templateId: 'tmpl_01ARZ3NDEKTSV4RRFFQ69G7FAK',
  },
  idempotencyKey: 'send-email:01ARZ3NDEKTSV4RRFFQ69G7FAK',
  tenantId: '01ARZ3NDEKTSV4RRFFQ69G7FAK',
  attempts: 0,
  backoff: { type: 'exponential', delay: 1000 },
  timeout: 30000,
}
```

---

## Exactly-Once Semantics

### Idempotency Key

Every job includes an idempotency key derived from the operation. Duplicate jobs with the same key are rejected.

```typescript
function generateIdempotencyKey(operation: string, tenantId: TenantId, payload: object): string {
  const hash = crypto.createHash('sha256')
    .update(`${operation}:${tenantId}:${JSON.stringify(payload)}`)
    .digest('hex');
  return `${operation}:${hash.slice(0, 32)}`;
}
```

### Deduplication

Before processing a job, workers check if a job with the same idempotency key was already processed:

```typescript
async function processJob(job: QueueJob): Promise<void> {
  // Check if already processed
  const exists = await this.idempotencyStore.exists(job.idempotencyKey);
  if (exists) {
    return; // Skip duplicate
  }

  // Process job
  await doWork(job.data);

  // Mark as processed
  await this.idempotencyStore.set(job.idempotencyKey, 'processed', { ttl: 86400 });
}
```

---

## Failure Handling

### Retry Strategy

Jobs fail and retry according to their policy. After exhaustion, jobs move to dead-letter queue (DLQ).

```
Job fails → Wait backoff delay → Retry → Fail → Retry → ... → Exhaust retries → DLQ
```

### DLQ Processing

Failed jobs in DLQ require manual intervention:

1. Analyze failure reason
2. Fix underlying issue
3. Replay job with new idempotency key
4. Monitor for success

### Circuit Breaker

When a provider fails repeatedly, the circuit breaker opens:

- After 5 failures in 30 seconds → Open
- After 30 seconds → Half-open (allow test requests)
- If test succeeds → Closed
- If test fails → Open again

---

## Benefits

### Resilience

Queue-first design prevents cascading failures. If a provider is down, jobs queue and retry later.

### Scalability

Workers scale independently from API nodes. More workers = more throughput.

### Observability

Every job tracked from enqueue to completion. Failed jobs audited in DLQ.

### Ordering

Jobs for the same tenant process in order. Parallel processing across tenants.

---

## Related Documents

- `event-driven-runtime.md`
- `replay-safe-design.md`
- `16-failure-models/queue-storms.md`
- `16-failure-models/provider-outages.md`
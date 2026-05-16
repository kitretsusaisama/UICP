# UICP Queue-First Philosophy

## Metadata

```yaml
title: UICP Queue-First Philosophy
domain: architecture
owner: Platform Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - architecture-summary.md
  - platform-philosophy.md
related-docs:
  - engineering-principles.md
  - operational-thinking.md
related-queues:
  - email-delivery
  - sms-delivery
  - otp-fastlane
  - webhook-processing
  - audit-logging
  - token-refresh
related-services:
  - communication-service
  - auth-service
  - token-service
  - audit-service
related-providers:
  - twilio
  - sendgrid
  - aws-ses
  - postmark
  - vonage
related-runtime-states:
  - running
  - degraded
  - recovering
related-threat-models:
  - queue-storm
  - provider-outage
  - redis-degradation
```

---

## Philosophy Overview

UICP adopts a **queue-first** architecture for all external operations. This means every operation that involves external systems (email delivery, SMS, webhooks, audit logging) is asynchronously processed through BullMQ rather than executed synchronously.

The rationale is straightforward: external systems fail. When they do, we want to fail gracefully, not catastrophically.

---

## BullMQ Architecture

UICP uses BullMQ as its queue backbone. BullMQ provides:

- **Job Persistence** — Jobs survive restarts
- **Cluster Support** — Horizontal scaling
- **Delayed Jobs** — Schedule future execution
- **Rate Limiting** — Per-worker throttling
- **Dead Letter Queues** — Poison message handling
- **Prioritization** — Urgent vs background jobs

### Queue Configuration

```typescript
// Email delivery queue with enterprise-grade settings
const emailQueue = new Queue('email-delivery', {
  connection: redisConnection,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 1000,
    },
    removeOnComplete: true,
    removeOnFail: 1000,
    timeout: 30000,
  },
});
```

### Retry Strategy

| Attempt | Delay | Strategy |
|---------|-------|----------|
| 1 | 1s | Immediate retry |
| 2 | 2s | Exponential backoff |
| 3 | 4s | Final attempt with escalation |

---

## Queue Categories

### Critical Queues (High Priority)
- `otp-fastlane` — Time-sensitive OTP delivery
- `token-refresh` — JWT refresh operations

### Standard Queues (Normal Priority)
- `email-delivery` — Transactional emails
- `sms-delivery` — SMS notifications
- `webhook-processing` — Outbound webhooks

### Background Queues (Low Priority)
- `audit-logging` — Compliance audit records
- `analytics-export` — Data export jobs

---

## Idempotency Guarantee

Every queue job must be idempotent. UICP generates ULID-based idempotency keys:

```typescript
interface QueueJob {
  id: string;              // BullMQ job ID
  idempotencyKey: string; // ULID for deduplication
  tenantId: string;        // Tenant context
  payload: object;        // Job payload
  attempts: number;       // Retry count
}
```

The processor checks for existing records before processing:

```typescript
async function processEmailJob(job: Job) {
  const { idempotencyKey, tenantId } = job.data;

  // Check for duplicate
  const existing = await this.eventStore.findByIdempotencyKey(idempotencyKey);
  if (existing) {
    this.logger.warn(`Duplicate job detected: ${idempotencyKey}`);
    return;
  }

  // Process with ULID idempotency key
  await this.emailProvider.send(job.data);
  await this.eventStore.record(idempotencyKey, job.data, tenantId);
}
```

---

## Dead Letter Strategy

When a job fails all retry attempts, it moves to the dead letter queue (DLQ).

### DLQ Handling Process
1. Job reaches max attempts (3 by default)
2. Job moved to `<queue-name>-dlq`
3. Alert triggered for ops team
4. Manual investigation via job data
5. Replay or discard decision

### Monitoring DLQ
- **DLQ Depth Alert** — >10 messages triggers PagerDuty
- **DLQ Growth Trend** — Tracks failure patterns
- **Message Retention** — 7 days for investigation

---

## Queue Health Metrics

| Metric | Alert Threshold | Action |
|--------|-----------------|--------|
| Queue Depth | >10,000 | Backpressure / scale workers |
| Processing Time | >30s avg | Investigate worker performance |
| Failure Rate | >5% | Check provider availability |
| DLQ Growth | >10 messages | Immediate investigation |
| Wait Time | >60s | Scale workers / check concurrency |

---

## Failure Modes and Mitigation

### Provider Outage
- Job retries with backoff
- Auto-failover to backup provider
- DLQ if all providers fail

### Redis Degradation
- BullMQ maintains job state in Redis
- If Redis is slow, queue operations slow
- Circuit breaker on queue operations

### Worker Crash
- Jobs marked as stalled after timeout
- Stalled jobs re-processed by another worker
- Job data preserved in Redis

---

## Best Practices

1. **Always use idempotency keys** — Never process duplicate jobs
2. **Keep payloads small** — <10KB recommended
3. **Set appropriate timeouts** — Match provider SLA
4. **Use named jobs** — Easier debugging and tracing
5. **Log context** — Include tenantId, keyId, correlationId
6. **Monitor DLQ** — Zero-tolerance for growing DLQ

---

## Comparison: Queue-First vs Synchronous

| Aspect | Queue-First | Synchronous |
|--------|-------------|-------------|
| Response Time | <50ms always | Provider-dependent |
| Failure Handling | Auto-retry | Manual retry |
| Scaling | Decoupled workers | Tightly coupled |
| Debugging | Full job history | Lost on timeout |
| Cost | Background processing | Peak-time premium |

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*
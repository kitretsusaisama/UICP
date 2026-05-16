# Replay-Safe Processing

## Metadata
```yaml
title: Replay-Safe Processing
domain: queues
owner: Platform Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: HIGH
queue-impact: CRITICAL
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-overview.md
  - retry-engine.md
  - dead-letter.md
related-docs:
  - 16-failure-models/duplicate-processing.md
  - 05-security/idempotency-keys.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
  - webhook-processing
  - audit-logging
related-services:
  - BullMQ worker service
  - MySQL database
  - Redis cluster
related-providers:
  - Twilio (SMS)
  - SendGrid (Email)
  - External webhook targets
related-runtime-states:
  - PROCESSING
  - COMPLETED
  - DUPLICATE_REJECTED
  - PARTIAL_COMPLETION
related-threat-models:
  - Duplicate payment processing
  - OTP resend abuse
  - Audit log gaps
  - State inconsistency after replay
```

---

## Overview

Replay-safe processing ensures that queue jobs can be safely retried or replayed without causing duplicate side effects, data corruption, or inconsistent state. This is critical for financial transactions, OTP delivery, and audit logging operations.

---

## Idempotency Implementation

### Idempotency Keys

Every queue job carries an idempotency key derived from:
- Operation type
- Tenant ID
- Business entity IDs
- Payload hash

```typescript
function generateIdempotencyKey(job: Job): string {
  const payload = `${job.type}:${job.tenantId}:${job.entityId}:${hash(job.payload)}`;
  return createSHA256(payload);
}
```

### Deduplication Check

Before processing, the worker checks Redis for existing completion:

```
1. Check Redis: EXISTS idempotency:{key}
2. If exists → return cached result (duplicate)
3. If not exists → SET idempotency:{key} with 24h TTL, process job
4. On completion → UPDATE idempotency key with result
```

TTL is configured per operation type:
- OTP: 300 seconds (5 minutes)
- SMS: 3600 seconds (1 hour)
- Email: 86400 seconds (24 hours)
- Webhooks: 3600 seconds (1 hour)

---

## Safe Replay Mechanisms

### Database Transaction Safety

All stateful operations use database transactions with savepoints:

```typescript
async function processJob(job: Job): Promise<void> {
  await db.transaction(async (trx) => {
    // Check idempotency within transaction
    const existing = await trx('processing_log')
      .where('idempotency_key', job.idempotencyKey)
      .first();

    if (existing && existing.status === 'COMPLETED') {
      return existing.result; // Safe replay returns cached result
    }

    // Process operation
    const result = await performOperation(job, trx);

    // Record completion
    await trx('processing_log').insert({
      idempotency_key: job.idempotencyKey,
      status: 'COMPLETED',
      result: result,
      processed_at: new Date()
    });

    return result;
  });
}
```

### Partial Completion Handling

For multi-step operations, each step is independently idempotent:
- Step completion recorded in database
- Replay starts from last incomplete step
- Checkpoint mechanism prevents re-execution of completed steps

---

## Race Condition Prevention

### Distributed Locking

Jobs acquire Redis-based distributed locks before processing:

```typescript
const lock = await redis.acquireLock({
  resource: `job:${job.id}`,
  ttl: 300000, // 5 minutes max processing time
  owner: workerId
});

if (!lock) {
  throw new Error('Job already being processed');
}

try {
  await processJob(job);
} finally {
  await lock.release();
}
```

### Leader Election for Multi-Worker

When multiple workers attempt the same job:
- First worker to acquire lock proceeds
- Others receive "duplicate job" signal
- Job marked as processed after lock acquisition timeout

---

## Audit Trail Integrity

### Processing Log Schema

```sql
CREATE TABLE processing_log (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  idempotency_key VARCHAR(64) NOT NULL UNIQUE,
  job_id VARCHAR(36) NOT NULL,
  tenant_id VARCHAR(36) NOT NULL,
  operation_type VARCHAR(50) NOT NULL,
  status ENUM('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED') NOT NULL,
  request_payload JSON,
  response_payload JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP NULL,
  INDEX idx_idempotency (idempotency_key),
  INDEX idx_tenant_operation (tenant_id, operation_type)
);
```

### Log Retention

- Completed operations: 90 days
- Failed operations: 365 days (for dispute resolution)
- Audit logs: 7 years (compliance requirement)

---

## Security Considerations

### Idempotency Key Security

- Keys are cryptographically random (256-bit entropy)
- Tenant isolation enforced at Redis key prefix level
- Keys include tenant ID to prevent cross-tenant collision

### Replay Attack Prevention

- Timestamps embedded in idempotency keys expire after TTL
- Request signing prevents key forgery
- Rate limiting on replay attempts per tenant

---

## Monitoring and Alerting

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `uicp.idempotency.duplicates` | Duplicate job detections | > 100/min |
| `uicp.idempotency.cache.hit_rate` | Cache hit ratio | < 80% |
| `uicp.processing.race_conditions` | Race condition detected | > 0 |
| `uicp.replay.safety.violations` | Safety violations | > 0 |

---

## Related Documents

- `09-queues/queue-overview.md`
- `09-queues/retry-engine.md`
- `09-queues/dead-letter.md`
- `05-security/idempotency-keys.md`
- `16-failure-models/duplicate-processing.md`
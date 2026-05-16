# Queue Priorities

## Metadata
```yaml
title: Queue Priorities
domain: queues
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-overview.md
  - queue-topology.md
  - worker-concurrency.md
related-docs:
  - 07-deployment/scaling-strategy.md
  - 16-failure-models/priority-inversion.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
  - webhook-processing
  - audit-logging
related-services:
  - BullMQ
  - Redis cluster
  - Worker pods
related-providers:
  - All external providers
related-runtime-states:
  - PRIORITY_QUEUED
  - PRIORITY_ACTIVE
  - PRIORITY_STARVED
related-threat-models:
  - Priority inversion attacks
  - Resource starvation
  - Queue flooding via low-priority
```

---

## Overview

Queue priority determines the order in which jobs are processed. UICP implements a multi-tier priority system that ensures critical operations like OTP delivery are processed with minimal latency while maintaining fair resource allocation for lower-priority operations.

---

## Priority Levels

### Tier 1: CRITICAL (otp-fastlane)

**Weight**: 70% of total capacity

Processes OTP generation and delivery with strict SLAs:
- Maximum wait time: 500ms at p99
- No queue delays permitted
- Dedicated worker pool
- Immediate failure on provider error

**Use cases**:
- OTP SMS delivery
- OTP email delivery
- Authentication verification

### Tier 2: HIGH (sms-delivery)

**Weight**: 20% of total capacity

Handles SMS delivery with retry capability:
- Maximum wait time: 2s at p99
- Exponential backoff on failure
- DLQ after 5 failed attempts

**Use cases**:
- Transactional SMS
- Alert notifications
- Marketing messages (non-critical)

### Tier 3: MEDIUM (email-delivery)

**Weight**: 7% of total capacity

Email delivery with reliable retry:
- Maximum wait time: 5s at p99
- Exponential backoff with longer delays
- DLQ after 5 failed attempts

**Use cases**:
- Transactional email
- User notifications
- System alerts

### Tier 4: LOW (webhook-processing, audit-logging)

**Weight**: 3% of total capacity

Best-effort processing with tolerance:
- Maximum wait time: 30s at p99
- DLQ after 3 failed attempts

**Use cases**:
- Webhook event handling
- Audit log persistence
- Analytics processing

---

## Priority Implementation

### BullMQ Priority Support

BullMQ supports priority levels 1-100:

```typescript
const queue = new Queue('queue-name', {
  connection: redisConnection,
  defaultJobOptions: {
    priority: 50, // Default priority
    removeOnComplete: true,
    removeOnFail: false
  }
});

// Job with explicit priority
await queue.add('job-name', data, {
  priority: Priority.CRITICAL // 1-100, lower is higher priority
});
```

### Priority Mapping

| Queue | BullMQ Priority | Internal Level |
|-------|-----------------|----------------|
| otp-fastlane | 1 | CRITICAL |
| sms-delivery | 20 | HIGH |
| email-delivery | 50 | MEDIUM |
| webhook-processing | 80 | LOW |
| audit-logging | 80 | LOW |

---

## Preemption Rules

When CRITICAL jobs enter a busy system:

1. Idle workers immediately pick CRITICAL jobs
2. Workers processing LOW jobs complete current job but don't pick more
3. Workers processing MEDIUM jobs finish current, yield to CRITICAL
4. If capacity exhausted, CRITICAL jobs queue but skip ahead of waiting lower priority

### Implementation

```typescript
async function getNextJob(worker: Worker): Promise<Job | null> {
  const queues = [
    { name: 'otp-fastlane', priority: 1 },
    { name: 'sms-delivery', priority: 20 },
    { name: 'email-delivery', priority: 50 },
    { name: 'webhook-processing', priority: 80 },
    { name: 'audit-logging', priority: 80 }
  ];

  for (const queue of queues) {
    const job = await queue.getNextJob(worker);
    if (job) return job;
  }

  return null;
}
```

---

## Fairness Within Priority

Jobs within the same priority level are processed FIFO:

- Insertion order preserved
- Equal processing opportunity
- No job starvation within tier

---

## Monitoring Priority Health

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `uicp.priority.critical.wait_time` | Critical queue wait | > 500ms |
| `uicp.priority.critical.starved` | Critical jobs starved | > 0 |
| `uicp.priority.low.wait_time` | Low priority wait | > 60s |
| `uicp.priority.inversion` | Priority inversion detected | > 0 |

---

## Security Considerations

### Priority Manipulation Prevention

- Priority set by system, not user-provided
- Tenant isolation enforced
- Admin override requires elevated permissions
- Audit trail for priority changes

---

## Related Documents

- `09-queues/queue-overview.md`
- `09-queues/queue-topology.md`
- `09-queues/worker-concurrency.md`
- `16-failure-models/priority-inversion.md`
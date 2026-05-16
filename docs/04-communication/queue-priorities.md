# Queue Priorities

## Metadata
```yaml
title: Queue Priorities
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: LOW
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - communication-overview.md
  - provider-runtime.md
related-docs:
  - retry-policies.md
  - fallback-policies.md
  - provider-failure-handling.md
related-queues:
  - email-delivery
  - sms-delivery
  - otp-fastlane
related-services:
  - QueueManager
  - MessageProcessor
  - PriorityRouter
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - queue_pending
  - queue_processing
  - queue_deferred
  - queue_completed
  - queue_failed
related-threat-models:
  - Queue saturation
  - Priority inversion
```

---

## Overview

Queue Priorities manage message processing order using BullMQ priority queues. Critical messages like OTPs are processed immediately while bulk emails are processed during off-peak hours.

---

## Queue Configuration

### Primary Queues

| Queue | Priority | Concurrency | TTL |
|-------|----------|--------------|-----|
| otp-fastlane | CRITICAL | 50 | 60s |
| sms-delivery | HIGH | 30 | 300s |
| email-delivery | MEDIUM | 20 | 600s |
| email-bulk | LOW | 5 | 3600s |

### Priority Levels

```typescript
enum QueuePriority {
  CRITICAL = 1,
  HIGH = 2,
  MEDIUM = 3,
  LOW = 4
}
```

---

## Message Classification

### Automatic Priority Assignment

```typescript
function determinePriority(message: OutboundMessage): QueuePriority {
  // OTPs always critical
  if (message.type === 'otp') return QueuePriority.CRITICAL;

  // Transactional emails high priority
  if (message.category === 'transactional') return QueuePriority.HIGH;

  // Marketing emails low priority
  if (message.category === 'marketing') return QueuePriority.LOW;

  // Default to medium
  return QueuePriority.MEDIUM;
}
```

### Tenant Priority Override

```typescript
interface TenantPriorityConfig {
  tenantId: string;
  defaultPriority: QueuePriority;
  maxPriority: QueuePriority;
  allowDowngrade: boolean;
  priorityBoost?: {
    premium: boolean;
    highValue: boolean;
  };
}
```

---

## Processing Logic

### Worker Configuration

```typescript
const emailWorker = new Worker('email-delivery', async job => {
  const priority = job.data.priority;
  const waitTime = (priority - 1) * 1000; // Higher priority = less wait

  await processWithBackoff(job.data, { maxRetries: 3 });
}, {
  concurrency: settings.concurrency,
  maxJobsPerWorker: 100
});
```

### Rate Limiting

```typescript
async function checkRateLimit(tenantId: string, messageType: string): Promise<boolean> {
  const key = `rate:${tenantId}:${messageType}`;
  const current = await redis.incr(key);

  if (current === 1) {
    await redis.expire(key, 3600); // 1 hour window
  }

  const limit = getLimit(tenantId, messageType);
  return current <= limit;
}
```

---

## Queue Management

### Backpressure Handling

When queue depth exceeds threshold:

1. Accept new messages
2. Mark as deferred
3. Process when capacity available
4. Notify tenant of delays

### Dead Letter Queue

Failed messages after max retries:

```typescript
const dlqConfig = {
  maxRetries: 3,
  backoff: {
    type: 'exponential',
    delay: 1000
  },
  removeOnComplete: {
    age: 3600,
    count: 1000
  },
  removeOnFail: {
    age: 604800,
    count: 10000
  }
};
```

---

## Monitoring

### Queue Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|------------------|
| queue_depth | Messages waiting | > 1000 |
| processing_time | Avg job duration | > 5s |
| wait_time | Time in queue | > 60s |
| throughput | Messages/min | < expected |

---

## Related Documents

- `04-communication/communication-overview.md`
- `04-communication/retry-policies.md`
- `04-communication/fallback-policies.md`
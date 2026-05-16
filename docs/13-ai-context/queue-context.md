# Queue Context - AI Context

## Metadata
```yaml
title: Queue Context
domain: ai-context
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: CRITICAL
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - retry-model.md
  - fallback-model.md
related-docs:
  - 07-async-processing/queue-architecture.md
  - 08-message-delivery/delivery-guarantees.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
  - webhook-processing
related-services:
  - notification-service
  - worker-pool
  - provider-router
related-runtime-states:
  - processing
  - pending
  - failed
  - dlq
```

---

## Queue Topology

| Queue | Priority | Consumer Group | Failure Impact |
|-------|----------|----------------|----------------|
| otp-fastlane | CRITICAL | otp-workers | Login failures |
| sms-delivery | HIGH | sms-workers | OTP delivery failures |
| email-delivery | MEDIUM | email-workers | Notification delays |
| webhook-processing | LOW | webhook-workers | Event sync gaps |

---

## Message Format

```typescript
interface QueueMessage {
  id: string;           // ULID
  tenant_id: string;   // Required for tenant isolation
  type: string;        // message type
  payload: object;     // type-specific data
  idempotency_key: string; // Required for dedup
  priority: number;    // lower = higher priority
  retry_count: number; // tracking
  created_at: string;  // ISO 8601
}
```

---

## Processing Rules

1. **Tenant Isolation**: All messages include tenant_id
2. **Idempotency**: Processing requires idempotency_key check
3. **Ordering**: FIFO within priority level
4. **Acknowledgment**: Manual ack after successful processing

---

## Queue Lifecycle

```
PENDING → PROCESSING → COMPLETED
              │
              ▼
           FAILED → RETRY (max 3)
              │
              ▼
             DLQ (after max retries)
```

---

## Backpressure Strategies

| Condition | Action |
|-----------|--------|
| Queue depth > 10k | Pause new submissions |
| Consumer lag > 5min | Scale workers |
| DLQ depth > 1k | Alert on-call |
| Provider down | Queue messages |

---

## Failure Impact Matrix

| Queue | Failure Impact | Recovery Time |
|-------|----------------|---------------|
| otp-fastlane | Complete login failure | < 1 min |
| sms-delivery | OTP delivery failure | < 5 min |
| email-delivery | Notification delay | < 30 min |
| webhook-processing | Event sync gap | < 1 hour |

---

## Related Context Files

- `retry-model.md` - Retry policies
- `fallback-model.md` - Provider fallback
- `system-summary.md` - Queue summary

---

*AI-Ingestible: true | Queue context for AI processing*
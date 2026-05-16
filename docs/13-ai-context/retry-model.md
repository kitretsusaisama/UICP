# Retry Model - AI Context

## Metadata
```yaml
title: Retry Model
domain: ai-context
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - queue-context.md
  - fallback-model.md
related-docs:
  - 07-async-processing/retry-policies.md
  - 08-message-delivery/retry-strategy.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
  - webhook-processing
related-services:
  - worker-pool
  - notification-service
related-runtime-states:
  - retrying
  - failed
  - dlq
```

---

## Retry Configuration

| Queue | Max Retries | Backoff | Dead Letter |
|-------|-------------|---------|-------------|
| otp-fastlane | 3 | exponential (1s, 2s, 4s) | Yes (critical) |
| sms-delivery | 3 | exponential (2s, 4s, 8s) | Yes |
| email-delivery | 5 | linear (5s, 10s, 15s...) | Yes |
| webhook-processing | 2 | fixed (10s) | No (low priority) |

---

## Retry Algorithm

```
1. Execute operation
2. If success → acknowledge, done
3. If failure →
   a. Check if retryable
   b. If not → send to DLQ
   c. If retryable → increment retry_count
   d. If retry_count < max → schedule retry with backoff
   e. If retry_count >= max → send to DLQ
```

---

## Retryable vs Non-Retryable

### Retryable Errors
- Timeout (provider unresponsive)
- Rate limit (429 response)
- Network error (connection reset)
- Service unavailable (503)

### Non-Retryable Errors
- Invalid request (400) - bad payload
- Authentication failure (401) - bad credentials
- Not found (404) - resource doesn't exist
- Payload too large (413)

---

## Backoff Strategy

| Attempt | Delay (exponential) | Delay (linear) |
|---------|---------------------|----------------|
| 1 | 1s | 5s |
| 2 | 2s | 10s |
| 3 | 4s | 15s |
| 4 | 8s | 20s |
| 5 | 16s | 25s |

---

## Retry Context

```typescript
interface RetryContext {
  retry_count: number;
  last_error: string;
  next_retry_at: Date;
  idempotency_key: string;
  tenant_id: string;
}
```

---

## Related Context Files

- `queue-context.md` - Queue definitions
- `fallback-model.md` - Failover logic
- `incident-model.md` - Failure handling

---

*AI-Ingestible: true | Retry context for AI understanding*
# Retry Engine

## Metadata
```yaml
title: Retry Engine
domain: queues
owner: Platform Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: CRITICAL
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-overview.md
  - dead-letter.md
  - failure-recovery.md
related-docs:
  - 16-failure-models/queue-storms.md
  - 08-monitoring/alerting-thresholds.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
  - webhook-processing
related-services:
  - BullMQ worker service
  - Redis cluster
related-providers:
  - Twilio (SMS)
  - SendGrid (Email)
  - Webhook endpoints
related-runtime-states:
  - RETRY_BACKOFF
  - RETRY_IMMEDIATE
  - DEAD_LETTER
  - EXPIRED
related-threat-models:
  - Retry storm amplification
  - Provider rate limit exhaustion
  - Resource exhaustion via retry loops
```

---

## Overview

The retry engine implements intelligent retry logic for failed queue jobs, protecting against transient failures while preventing cascade failures. UICP's retry engine supports both exponential backoff for external API calls and immediate failure for critical path operations.

---

## Retry Strategies

### Exponential Backoff (Email, SMS, Webhooks)

Used for non-critical external API calls where temporary failures are expected:

```
Attempt 1: Immediate (0s delay)
Attempt 2: 1 second delay
Attempt 3: 4 seconds delay (2^2)
Attempt 4: 16 seconds delay (2^4)
Attempt 5: 64 seconds delay (2^6)
Attempt 6+: Dead letter queue
```

Configuration parameters:
- `maxAttempts`: 5
- `baseDelay`: 1000ms
- `maxDelay`: 60000ms
- `strategy`: exponential
- `jitter`: true (prevents thundering herd)

### Immediate Retry (OTP)

Used for critical path operations where delayed retry causes user experience issues:

```
Attempt 1: Immediate
Attempt 2: Dead letter queue (no additional retries)
```

Configuration parameters:
- `maxAttempts`: 2
- `delay`: 0ms
- `strategy`: none

---

## Implementation Details

### Backoff Calculation

```typescript
function calculateBackoff(attempt: number, options: RetryOptions): number {
  const exponentialDelay = Math.pow(options.baseDelay, Math.min(attempt, 10));
  const cappedDelay = Math.min(exponentialDelay, options.maxDelay);
  const jitter = Math.random() * 0.3 * cappedDelay; // 30% jitter
  return Math.floor(cappedDelay + jitter);
}
```

### Job State Transitions

```
ACTIVE → RETRY_WAIT → ACTIVE → RETRY_WAIT → ACTIVE → DEAD_LETTER
         (delayed job)           (delayed job)
```

Delayed jobs are stored in Redis with score set to execution timestamp, allowing BullMQ to reschedule automatically.

---

## Circuit Breaker Integration

The retry engine integrates with the circuit breaker to prevent hammering failing providers:

- After 5 consecutive failures on a provider, the circuit opens
- Retry engine bypasses the failing provider for configured duration
- After cooldown, half-open state allows test requests
- Successful requests close the circuit

---

## Security Considerations

### Rate Limiting Protection

- Each tenant has independent retry quotas
- Global retry rate limited to 1000 ops/second
- Per-provider rate limits enforced via circuit breaker

### Malicious Payload Handling

- Retry attempts validate message schema before processing
- Suspicious payloads are flagged for manual review
- Maximum payload size: 1MB

---

## Monitoring

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `uicp.retry.attempts` | Total retry attempts | > 1000/min |
| `uicp.retry.backoff.duration` | Average backoff time | > 30s |
| `uicp.retry.circuit.open` | Circuit breaker open | > 0 |
| `uicp.retry.dead_letter.rate` | DLQ placement rate | > 5% |

---

## Related Documents

- `09-queues/queue-overview.md`
- `09-queues/dead-letter.md`
- `09-queues/failure-recovery.md`
- `16-failure-models/queue-storms.md`
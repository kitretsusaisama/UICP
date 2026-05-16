# Retry Tuning

## Metadata
```yaml
title: Retry Tuning
domain: smart-tuning
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
  - 02-runtime/retry-runtime
  - 09-queues/queue-overview
  - 16-failure-models/provider-outages
related-docs:
  - 18-smart-tuning/provider-scoring.md
  - 18-smart-tuning/fallback-tuning.md
  - 18-smart-tuning/queue-tuning.md
related-queues:
  - Retry Queue
  - Dead Letter Queue
related-services:
  - Retry Manager
  - Queue Orchestrator
related-providers:
  - All providers
```

---

## Overview

Retry tuning configures how the system handles failed delivery attempts, balancing between aggressive retry attempts to maximize delivery success and avoiding behavior that could overwhelm providers or create duplicate deliveries. The retry mechanism is the primary defense against transient failures, making its configuration critical for both reliability and efficiency.

The retry system operates as an adaptive layer that responds to failure patterns, escalating retry intensity when failures appear systemic and backing off when they seem isolated. This adaptive approach reduces the manual configuration burden while improving outcomes across diverse failure scenarios.

---

## Retry Strategies

The system supports multiple retry strategies, selectable based on message characteristics and business requirements:

**Fixed Interval Retry** applies consistent delays between attempts, suitable for operations where order matters or when provider load should remain predictable. The interval duration is configurable per message type, with defaults of 5 seconds for standard messages and 30 seconds for high-priority communications.

**Exponential Backoff** doubles the delay between each retry attempt, reducing the likelihood of overwhelming a struggling provider while still ensuring eventual delivery. Initial delay starts at 1 second, growing to a maximum of 5 minutes before failing the message.

**Jittered Backoff** adds random variance to exponential backoff, preventing thundering herd scenarios where multiple clients retry simultaneously. The jitter ranges from -20% to +20% of the calculated backoff duration.

---

## Retry Limits and Boundaries

Maximum retry attempts are configured per message category, with different thresholds for different delivery types:

| Category | Max Retries | Total Timeout |
|----------|-------------|---------------|
| Transactional Email | 3 | 2 minutes |
| Promotional Email | 5 | 10 minutes |
| SMS | 3 | 1 minute |
| Webhooks | 3 | 3 minutes |
| Critical Alerts | 5 | 5 minutes |

These limits prevent infinite retry loops while ensuring sufficient attempts for likely recovery. The total timeout acts as a circuit breaker, terminating retries even when attempts remain available if the overall elapsed time exceeds the threshold.

---

## Circuit Breaker Integration

Retry tuning integrates with circuit breaker patterns to prevent sustained retry attempts against failing providers. When a provider's failure rate exceeds 50% over a 60-second window, the circuit breaker opens and immediate fallback occurs without retry attempts against the failed provider.

The circuit breaker auto-resets after 30 seconds of normal operation, allowing the system to recover when provider health improves. This integration prevents the retry system from amplifying downstream issues during major provider outages.

---

## Idempotency Considerations

All retryable messages must include idempotency keys to prevent duplicate deliveries when retries succeed after the original delivery actually succeeded but the acknowledgment was lost. The idempotency key is derived from the message payload hash combined with a tenant-specific salt, ensuring uniqueness across tenants while consistency within a tenant's message flow.

Retry attempts reuse the original idempotency key, allowing downstream systems to recognize and deduplicate repeated delivery attempts automatically. This mechanism is essential for ensuring that aggressive retry policies do not result in customer-facing duplicates.

---

## Retry Queue Management

Failed messages enter a retry queue with priority based on failure type and message criticality. The queue processing scheduler applies different polling frequencies based on priority, ensuring high-priority messages are reprocessed more quickly while avoiding excessive API calls for lower-priority failures.

Dead letter queue thresholds are enforced after all retries are exhausted, with messages remaining in the dead letter queue for 7 days before automatic cleanup. Alerting triggers when dead letter queue depth exceeds 1000 messages, indicating potential systemic issues requiring investigation.

---

## Related Documents

- `18-smart-tuning/provider-scoring.md`
- `18-smart-tuning/fallback-tuning.md`
- `18-smart-tuning/queue-tuning.md`
- `02-runtime/retry-runtime.md`
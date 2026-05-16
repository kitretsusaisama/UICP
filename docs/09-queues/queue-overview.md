# Queue Overview

## Metadata
```yaml
title: Queue Overview
domain: queues
criticality: HIGH
queue-impact: CRITICAL
ai-ingestable: true
```

---

## Overview

UICP uses BullMQ for async message processing. All external I/O operations (email, SMS, webhooks) flow through queues to ensure reliability, retry capability, and operational visibility.

---

## Queue Topology

| Queue | Priority | Description | DLQ |
|-------|----------|-------------|-----|
| `otp-fastlane` | CRITICAL | OTP generation & delivery | No |
| `sms-delivery` | HIGH | SMS message delivery | Yes |
| `email-delivery` | MEDIUM | Email message delivery | Yes |
| `webhook-processing` | LOW | Webhook event handling | Yes |
| `audit-logging` | LOW | Audit log persistence | Yes |

---

## Retry Policy

### Exponential Backoff (Email, SMS)
```
Attempt 1: Immediate
Attempt 2: 1 second delay
Attempt 3: 4 seconds delay
Attempt 4: 16 seconds delay
Attempt 5: Dead letter queue
```

### Immediate (OTP)
```
Attempt 1: Immediate
Attempt 2: Dead letter queue (no retries - critical path)
```

---

## Worker Configuration

| Queue | Concurrency | TTL |
|-------|-------------|-----|
| otp-fastlane | 50 | 300s |
| sms-delivery | 20 | 3600s |
| email-delivery | 10 | 7200s |
| webhook-processing | 5 | 3600s |
| audit-logging | 5 | 1800s |

---

## Dead Letter Queue

Messages that exceed max retries are moved to DLQ:
- Manual review required
- Replay via admin API
- Preserved for 30 days

---

## Observability

| Metric | Description |
|--------|-------------|
| `uicp.queue.backlog` | Messages pending |
| `uicp.queue.processing` | Messages being processed |
| `uicp.queue.completed` | Messages completed |
| `uicp.queue.failed` | Messages moved to DLQ |
| `uicp.queue.duration` | Processing time |

---

## Related Documents

- `09-queues/retry-engine.md`
- `09-queues/dead-letter.md`
- `16-failure-models/queue-storms.md`


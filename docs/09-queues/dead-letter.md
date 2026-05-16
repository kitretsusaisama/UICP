# Dead Letter Queue

## Metadata
```yaml
title: Dead Letter Queue
domain: queues
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-overview.md
  - retry-engine.md
  - failure-recovery.md
related-docs:
  - 04-operations/admin-replay-api.md
  - 16-failure-models/queue-storms.md
related-queues:
  - sms-dlq
  - email-dlq
  - webhook-dlq
  - audit-dlq
related-services:
  - BullMQ
  - Redis cluster
  - MySQL database
related-providers:
  - Twilio (SMS)
  - SendGrid (Email)
  - Custom webhook endpoints
related-runtime-states:
  - DEAD_LETTERED
  - REPLAY_REQUESTED
  - REPLAY_IN_PROGRESS
  - REPLAY_FAILED
  - PERMANENT_FAILURE
related-threat-models:
  - DLQ accumulation attacks
  - Data leakage via DLQ
  - Replay exploitation
```

---

## Overview

Dead Letter Queues (DLQs) capture jobs that have exhausted all retry attempts. These jobs require manual intervention or programmatic replay to process. DLQs serve as a safety net ensuring no message is silently lost while providing diagnostic data for failure analysis.

---

## DLQ Architecture

### Queue Mapping

| Source Queue | DLQ Name | Max Retries | Retry Strategy |
|--------------|----------|-------------|----------------|
| sms-delivery | sms-dlq | 5 | Exponential backoff |
| email-delivery | email-dlq | 5 | Exponential backoff |
| webhook-processing | webhook-dlq | 3 | Exponential backoff |
| audit-logging | audit-dlq | 3 | Exponential backoff |

### Special Case: otp-fastlane

The otp-fastlane queue has no DLQ:
- OTP failures are synchronous errors
- User receives immediate failure response
- No async retry to prevent confusion
- Failed OTP requests logged for audit

---

## Job Structure in DLQ

### Preserved Metadata

When jobs move to DLQ, the following is preserved:

```typescript
interface DeadLetterJob {
  id: string;
  originalQueue: string;
  attempts: number;
  maxAttempts: number;
  failedAt: Date;
  failureReason: string;
  errorMessage: string;
  errorStack: string;
  payload: object;
  idempotencyKey: string;
  tenantId: string;
  priority: number;
  previousAttempts: Attempt[];
}

interface Attempt {
  attemptNumber: number;
  startedAt: Date;
  endedAt: Date;
  error: string;
  workerId: string;
}
```

---

## Retention Policy

### TTL Configuration

| DLQ | Retention Period | Auto-Delete |
|-----|-----------------|-------------|
| sms-dlq | 30 days | Yes |
| email-dlq | 30 days | Yes |
| webhook-dlq | 30 days | Yes |
| audit-dlq | 365 days | No (compliance) |

### Cleanup Process

- Daily scan for expired DLQ jobs
- Archive to cold storage before deletion (compliance only)
- Soft delete in database (recoverable for 7 days)
- Hard delete after 90 days

---

## Replay Mechanisms

### Admin API Replay

```typescript
// POST /api/v1/admin/queues/replay
{
  "dlq_name": "sms-dlq",
  "job_ids": ["job-uuid-1", "job-uuid-2"],
  "options": {
    "priority": "HIGH",
    "delay_seconds": 0,
    "max_attempts": 3
  }
}
```

### Bulk Replay

```typescript
// POST /api/v1/admin/queues/bulk-replay
{
  "dlq_name": "email-dlq",
  "filter": {
    "failed_after": "2026-04-01",
    "failed_before": "2026-04-15",
    "tenant_id": "tenant-123"
  },
  "limit": 1000
}
```

---

## Manual Review Workflow

### Investigation Steps

1. **Identify**: Query DLQ for failed jobs
2. **Analyze**: Review error messages and stack traces
3. **Reproduce**: Create test case to reproduce failure
4. **Fix**: Apply code fix or configuration change
5. **Verify**: Replay single job to verify fix
6. **Deploy**: Deploy fix to production
7. **Bulk Replay**: Replay remaining failed jobs

### Review Dashboard

| Metric | Description |
|--------|-------------|
| DLQ depth | Current jobs in each DLQ |
| Age distribution | How long jobs have been in DLQ |
| Failure patterns | Common error types |
| Resolution time | Time from failure to resolution |

---

## Security Considerations

### Data Protection

- DLQ jobs contain PII (phone numbers, emails)
- Encrypted at rest in Redis
- Access restricted to admin role
- Audit log for all DLQ access

### Replay Authorization

- Replay requires admin authentication
- Tenant isolation enforced
- Rate limited: 100 jobs per minute max
- All replays logged for audit

---

## Monitoring

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `uicp.dlq.depth` | DLQ size per queue | > 1000 |
| `uicp.dlq.growth_rate` | New DLQ entries per hour | > 100/hr |
| `uicp.dlq.retention.violations` | Over retention limit | > 0 |
| `uicp.dlq.replay.success_rate` | Replay success rate | < 80% |

---

## Related Documents

- `09-queues/queue-overview.md`
- `09-queues/retry-engine.md`
- `09-queues/failure-recovery.md`
- `04-operations/admin-replay-api.md`
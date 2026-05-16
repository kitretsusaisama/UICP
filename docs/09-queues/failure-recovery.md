# Failure Recovery

## Metadata
```yaml
title: Failure Recovery
domain: queues
owner: Platform Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: CRITICAL
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-overview.md
  - retry-engine.md
  - dead-letter.md
related-docs:
  - 16-failure-models/queue-storms.md
  - 16-failure-models/cascade-failures.md
  - 04-operations/incident-response.md
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
  - Database
related-providers:
  - Twilio (SMS)
  - SendGrid (Email)
  - Webhook endpoints
related-runtime-states:
  - FAILING
  - RETRYING
  - RECOVERING
  - DEGRADED
  - HEALTHY
related-threat-models:
  - Cascading failures
  - Resource exhaustion
  - Data loss during recovery
```

---

## Overview

Failure recovery ensures the system gracefully handles and recovers from various failure scenarios. This document covers recovery strategies for worker failures, provider outages, infrastructure issues, and data inconsistencies.

---

## Failure Scenarios

### Worker Failure

**Detection**: Worker pod terminates unexpectedly

**Recovery Steps**:
1. Kubernetes restarts worker pod
2. BullMQ detects worker disconnection
3. Active jobs automatically reassigned to available workers
4. Lock timeout expires (30s default) triggers job release
5. Jobs return to queue with retry increment

```typescript
// BullMQ handles this automatically:
// - Failed jobs have failedBefore callback
// - Job automatically retried based on retryStrategy
// - After max attempts, moves to DLQ
```

### Provider Outage

**Detection**: High error rate from external API (>20%)

**Recovery Steps**:
1. Circuit breaker opens
2. New jobs fail immediately (fast fail)
3. In-flight jobs complete or timeout
4. Queue depth increases (backlog)
5. Monitor backlog growth rate
6. Resolve root cause
7. Circuit closes on successful test requests

### Redis Failure

**Detection**: Redis cluster unreachable

**Recovery Steps**:
1. Worker detects connection loss
2. In-flight jobs marked as failed
3. Switch to read-only mode if possible
4. Alert on-call engineer
5. Restore Redis connectivity
6. Replay failed jobs from DB checkpoint

### Database Failure

**Detection**: Database connection errors

**Recovery Steps**:
1. Jobs in ACTIVE state checkpointed
2. Queue pauses new job processing
3. Alert database team
4. After DB recovery, resume processing
5. Verify no data loss via idempotency keys

---

## Recovery Procedures

### Immediate Recovery (First 5 Minutes)

1. **Assess scope**: Which queues affected?
2. **Check circuit breakers**: Open/closed state
3. **Verify worker health**: Pod status, logs
4. **Review recent changes**: Deployments, config

### Short-Term Recovery (5-30 Minutes)

1. **Scale workers**: Increase capacity if needed
2. **Clear DLQ backlog**: Replay safe jobs
3. **Contact providers**: Verify their status
4. **Update stakeholders**: Status page update

### Long-Term Recovery (30+ Minutes)

1. **Root cause analysis**: Post-mortem
2. **Fix implementation**: Code/config change
3. **Verify fix**: Test in staging
4. **Deploy fix**: Production release
5. **Monitor recovery**: Watch metrics normalize

---

## Checkpoint System

### Implementation

For long-running jobs, checkpoints prevent loss:

```typescript
class CheckpointableJob {
  async processWithCheckpoint(job: Job): Promise<void> {
    const checkpointKey = `checkpoint:${job.id}`;
    const lastCheckpoint = await redis.get(checkpointKey);

    if (lastCheckpoint) {
      // Resume from checkpoint
      await this.resumeFrom(lastCheckpoint);
    } else {
      // Start fresh
      await this.processFromStart();
    }
  }

  async saveCheckpoint(jobId: string, step: number): Promise<void> {
    await redis.set(`checkpoint:${jobId}`, step, { EX: 3600 });
  }
}
```

### Checkpoint Intervals

| Job Type | Checkpoint Interval |
|----------|-------------------|
| Bulk SMS | Every 100 messages |
| Email batch | Every 50 emails |
| Webhook batch | Every 20 webhooks |

---

## Data Consistency

### Idempotency Verification

After recovery, verify no duplicate processing:

```typescript
async function verifyNoDuplicates(tenantId: string): Promise<boolean> {
  const duplicates = await db.query(`
    SELECT idempotency_key, COUNT(*) as cnt
    FROM processing_log
    WHERE tenant_id = ?
    AND completed_at > NOW() - INTERVAL '1 hour'
    GROUP BY idempotency_key
    HAVING COUNT(*) > 1
  `);

  return duplicates.length === 0;
}
```

### Reconciliation

Run periodic reconciliation job:

```typescript
// Daily reconciliation
const reconciliation = {
  source: 'queue_metrics',
  target: 'processing_log',
  check: 'counts_match',
  alertOnMismatch: true,
  autoFix: false // Manual fix required
};
```

---

## Communication

### Status Updates

| Time | Audience | Content |
|------|----------|---------|
| Immediate | On-call | Alert notification |
| 15 min | Team | Initial assessment |
| 1 hour | Stakeholders | Current status |
| Post-incident | All | Post-mortem report |

---

## Monitoring Recovery

| Metric | Target | Alert |
|--------|--------|-------|
| Queue depth | Back to normal < 1000 | > 5000 |
| Error rate | < 1% | > 5% |
| Processing time | p99 < 5s | > 30s |
| DLQ entries | Zero new | > 10 |

---

## Related Documents

- `09-queues/queue-overview.md`
- `09-queues/retry-engine.md`
- `09-queues/dead-letter.md`
- `16-failure-models/queue-storms.md`
- `04-operations/incident-response.md`
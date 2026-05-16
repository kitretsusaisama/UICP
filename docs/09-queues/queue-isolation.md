# Queue Isolation

## Metadata
```yaml
title: Queue Isolation
domain: queues
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-overview.md
  - queue-topology.md
  - queue-priorities.md
related-docs:
  - 05-security/tenant-isolation.md
  - 16-failure-models/tenant-leakage.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
  - webhook-processing
  - audit-logging
related-services:
  - BullMQ
  - Redis cluster
  - MySQL database
related-providers:
  - All providers
related-runtime-states:
  - ISOLATED
  - QUOTA_EXCEEDED
  - THROTTLED
  - SHARED
related-threat-models:
  - Cross-tenant data access
  - Resource starvation by noisy neighbor
  - Tenant isolation bypass
```

---

## Overview

Queue isolation ensures each tenant's jobs are logically and physically separated from other tenants. This prevents data leakage, ensures fair resource allocation, and provides operational isolation for troubleshooting.

---

## Isolation Levels

### Level 1: Key Prefix Isolation

All Redis keys include tenant ID prefix:

```
Before: uicp:queue:sms-delivery:job:123
After:  uicp:tenant-abc:queue:sms-delivery:job:123
```

Implementation:

```typescript
function getQueueKey(queueName: string, tenantId: string): string {
  return `uicp:${tenantId}:queue:${queueName}`;
}

function getJobKey(jobId: string, tenantId: string): string {
  return `uicp:${tenantId}:job:${jobId}`;
}
```

### Level 2: Queue Partitioning

Tenants can optionally have dedicated queues:

```
Standard tenants: shared queues (tenant-abc:queue:sms-delivery)
Enterprise tenants: dedicated queues (sms-delivery-tenant-abc)
```

### Level 3: Resource Quotas

Per-tenant resource limits:

| Resource | Limit |
|----------|-------|
| Jobs per minute | 1000 |
| Concurrent jobs | 100 |
| Queue depth | 10000 |
| DLQ entries | 1000 |
| Retry attempts per hour | 5000 |

---

## Tenant Quota Enforcement

### Quota Check on Enqueue

```typescript
async function checkAndEnqueue(
  queueName: string,
  tenantId: string,
  jobData: object
): Promise<void> {
  const quota = await getTenantQuota(tenantId);

  // Check rate limit
  const currentRate = await getCurrentRate(tenantId);
  if (currentRate >= quota.maxRatePerMinute) {
    throw new QuotaExceededError('Rate limit exceeded');
  }

  // Check concurrent limit
  const currentConcurrent = await getConcurrentJobs(tenantId);
  if (currentConcurrent >= quota.maxConcurrent) {
    throw new QuotaExceededError('Concurrent limit exceeded');
  }

  // Enqueue job
  await enqueueJob(queueName, tenantId, jobData);
  await incrementRate(tenantId);
}
```

### Quota Monitoring

```typescript
setInterval(async () => {
  const quotas = await getAllTenantQuotas();

  for (const quota of quotas) {
    if (quota.usage > quota.limit * 0.8) {
      alert(`Tenant ${quota.tenantId} at ${quota.usage}/${quota.limit}`);
    }
  }
}, 60000); // Check every minute
```

---

## Isolation Verification

### Cross-Tenant Leak Test

```typescript
async function verifyIsolation(): Promise<boolean> {
  const testTenantA = 'tenant-a-test';
  const testTenantB = 'tenant-b-test';

  // Enqueue job for tenant A
  await queue.add('test-job', { data: 'test-a' }, {
    tenantId: testTenantA
  });

  // Attempt to read from tenant B
  const leakedData = await redis.get(`uicp:${testTenantA}:test-job:*`);

  // Should not be accessible
  return leakedData === null;
}
```

### Test Results

| Test | Expected | Actual | Status |
|------|----------|--------|--------|
| Key prefix | Isolated | Isolated | PASS |
| Queue access | Denied | Denied | PASS |
| DLQ access | Denied | Denied | PASS |
| Rate limit | Enforced | Enforced | PASS |

---

## Failure Isolation

### Blast Radius Limiting

When one tenant experiences issues:

1. **Quarantine**: Temporarily isolate affected tenant
2. **Throttle**: Reduce processing rate
3. **Circuit break**: Stop accepting new jobs
4. **Alert**: Notify tenant admin

```typescript
async function handleTenantFailure(tenantId: string): Promise<void> {
  const tenant = await getTenant(tenantId);

  // Mark tenant as degraded
  await setTenantState(tenantId, 'QUARANTINED');

  // Stop accepting new jobs
  await enableThrottling(tenantId);

  // Limit concurrent processing
  await setMaxConcurrent(tenantId, 10);

  // Alert
  await alertOnCall(`${tenant.name} in quarantine`);
}
```

### Recovery

```typescript
async function restoreTenant(tenantId: string): Promise<void> {
  const health = await checkTenantHealth(tenantId);

  if (health.isHealthy) {
    await setTenantState(tenantId, 'HEALTHY');
    await disableThrottling(tenantId);
    await setMaxConcurrent(tenantId, 100);
    await notifyTenantAdmin(tenantId, 'Service restored');
  }
}
```

---

## Multi-Tenant Architecture

```
┌─────────────────────────────────────────────┐
│              Redis Cluster                  │
│  ┌─────────────┐  ┌─────────────┐          │
│  │ Partition 1 │  │ Partition 2 │          │
│  │             │  │             │          │
│  │ tenant-a    │  │ tenant-c    │          │
│  │ tenant-b    │  │ tenant-d    │          │
│  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────┘
```

### Partition Strategy

- Hash-based partitioning by tenant ID
- Minimum 3 partitions for HA
- Rebalance when tenant count > 100

---

## Monitoring

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `uicp.isolation.leakage` | Cross-tenant access attempts | > 0 |
| `uicp.isolation.quota.throttled` | Throttled tenants | > 5 |
| `uicp.isolation.quarantine.active` | Quarantined tenants | > 0 |

---

## Related Documents

- `09-queues/queue-overview.md`
- `05-security/tenant-isolation.md`
- `16-failure-models/tenant-leakage.md`
# Queue Lineage

## Metadata
```yaml
title: Queue Lineage
domain: queues
owner: Platform Team
criticality: MEDIUM
runtime-impact: LOW
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-overview.md
  - queue-topology.md
  - replay-safe-processing.md
related-docs:
  - 05-security/audit-logging.md
  - 16-failure-models/tracing.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
  - webhook-processing
  - audit-logging
related-services:
  - BullMQ
  - MySQL database
  - Redis cluster
related-providers:
  - All providers
related-runtime-states:
  - LINEAGE_STARTED
  - LINEAGE_CHAINED
  - LINEAGE_COMPLETED
  - LINEAGE_FAILED
related-threat-models:
  - Lineage data leakage
  - Chain manipulation
  - Audit gap exploitation
```

---

## Overview

Queue lineage tracks the complete lifecycle of jobs, including parent-child relationships, state transitions, and processing history. Lineage enables debugging, compliance auditing, and impact analysis when issues occur.

---

## Lineage Data Model

### Job Graph

```
         [API Request]
              │
              ▼
        [otp-fastlane]
         /    |    \
        /     |     \
       ▼      ▼      ▼
   [email] [sms] [webhook]
    delivery delivery callback
```

### Lineage Record

```typescript
interface LineageRecord {
  id: string;
  rootJobId: string;
  parentJobId: string | null;
  childJobIds: string[];
  chainDepth: number;
  startedAt: Date;
  completedAt: Date | null;
  status: LineageStatus;
  totalJobs: number;
  completedJobs: number;
  failedJobs: number;
}

enum LineageStatus {
  STARTED = 'STARTED',
  IN_PROGRESS = 'IN_PROGRESS',
  COMPLETED = 'COMPLETED',
  PARTIALLY_COMPLETED = 'PARTIALLY_COMPLETED',
  FAILED = 'FAILED'
}
```

---

## Tracking Implementation

### Creating Lineage

```typescript
async function createLineage(parentJob: Job, childJobs: Job[]): Promise<void> {
  const lineage: LineageRecord = {
    id: generateULID(),
    rootJobId: parentJob.id,
    parentJobId: null,
    childJobIds: childJobs.map(j => j.id),
    chainDepth: 0,
    startedAt: new Date(),
    status: 'IN_PROGRESS'
  };

  await db('queue_lineage').insert(lineage);

  // Update parent job with lineage reference
  await parentJob.update({
    lineageId: lineage.id
  });
}
```

### Linking Child Jobs

```typescript
async function linkChildToParent(childJob: Job, parentLineageId: string): Promise<void> {
  const parentLineage = await db('queue_lineage')
    .where('id', parentLineageId)
    .first();

  await db('queue_lineage')
    .where('id', parentLineageId)
    .update({
      childJobIds: [...parentLineage.childJobIds, childJob.id],
      totalJobs: parentLineage.totalJobs + 1
    });
}
```

---

## Querying Lineage

### Get Full Chain

```typescript
async function getFullLineage(rootJobId: string): Promise<LineageRecord> {
  const lineage = await db('queue_lineage')
    .where('root_job_id', rootJobId)
    .first();

  const childLineages = await db('queue_lineage')
    .whereIn('id', lineage.childLineageIds);

  return {
    ...lineage,
    children: childLineages
  };
}
```

### Get Ancestors

```typescript
async function getAncestors(jobId: string): Promise<Job[]> {
  const ancestors: Job[] = [];
  let currentJobId: string | null = jobId;

  while (currentJobId) {
    const lineage = await db('queue_lineage')
      .where('child_job_ids', 'LIKE', `%${currentJobId}%`)
      .first();

    if (!lineage) break;

    const parentJob = await getJob(lineage.rootJobId);
    ancestors.push(parentJob);
    currentJobId = lineage.parentJobId;
  }

  return ancestors;
}
```

---

## Lineage Queries

### Impact Analysis

When a job fails, find downstream impact:

```typescript
async function analyzeImpact(failedJobId: string): Promise<ImpactReport> {
  const lineage = await getFullLineage(failedJobId);

  return {
    failedJob: failedJobId,
    totalDownstreamJobs: lineage.totalJobs,
    completedJobs: lineage.completedJobs,
    pendingJobs: lineage.totalJobs - lineage.completedJobs - lineage.failedJobs,
    affectedTenants: await getAffectedTenants(lineage),
    canRecover: lineage.failedJobs === 0 // All failed means can't recover
  };
}
```

### Root Cause Analysis

Trace failures back to origin:

```typescript
async function findRootCause(jobId: string): Promise<RootCauseReport> {
  const ancestors = await getAncestors(jobId);

  return {
    originalJob: ancestors[0],
    chainLength: ancestors.length,
    failures: await findFailuresInChain(ancestors),
    recommendations: generateRecommendations(ancestors)
  };
}
```

---

## Lineage Retention

| Record Type | Retention | Purpose |
|-------------|-----------|---------|
| Completed lineages | 30 days | Debugging |
| Failed lineages | 1 year | Compliance |
| Audit-extracted | 7 years | Regulatory |

---

## Security Considerations

### Access Control

- Lineage queries require read access to tenant data
- Cross-tenant lineage prohibited
- Admin override requires audit log entry

### Data Privacy

- Lineage records contain job IDs, not payloads
- Sensitive data in payloads not stored in lineage
- Export requires data team approval

---

## Monitoring

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `uicp.lineage.chains.active` | Active job chains | > 10000 |
| `uicp.lineage.depth.max` | Max chain depth | > 10 |
| `uicp.lineage.queries.slow` | Slow lineage queries | > 1s |
| `uicp.lineage.gaps` | Missing lineage records | > 0 |

---

## Related Documents

- `09-queues/queue-overview.md`
- `09-queues/replay-safe-processing.md`
- `05-security/audit-logging.md`
- `16-failure-models/tracing.md`
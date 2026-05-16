# Queue Capacity Planning

## Metadata
```yaml
title: Queue Capacity Planning
domain: queues
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-overview.md
  - queue-topology.md
  - worker-concurrency.md
  - provider-queues.md
related-docs:
  - 07-deployment/scaling-strategy.md
  - 03-architecture/infrastructure.md
  - 08-monitoring/capacity-dashboards.md
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
  - CAPACITY_NORMAL
  - CAPACITY_WARNING
  - CAPACITY_CRITICAL
  - CAPACITY_SCALING
related-threat-models:
  - Capacity exhaustion
  - Resource starvation
  - Cascade failure from overload
```

---

## Overview

Capacity planning ensures queue infrastructure can handle current and projected load. This document outlines capacity calculation methods, scaling triggers, and resource allocation strategies.

---

## Baseline Metrics

### Current Load (May 2026)

| Queue | Avg RPS | Peak RPS | Daily Volume | Storage/Day |
|-------|---------|----------|--------------|-------------|
| otp-fastlane | 50 | 200 | 4.3M | 500MB |
| sms-delivery | 30 | 100 | 2.6M | 300MB |
| email-delivery | 20 | 80 | 1.7M | 200MB |
| webhook-processing | 10 | 50 | 860K | 100MB |
| audit-logging | 5 | 20 | 430K | 50MB |

### Growth Projections

| Queue | 6-Month Projection | 12-Month Projection | 24-Month Projection |
|-------|-------------------|---------------------|---------------------|
| otp-fastlane | 2x | 4x | 8x |
| sms-delivery | 1.5x | 2.5x | 5x |
| email-delivery | 1.5x | 2x | 4x |
| webhook-processing | 2x | 4x | 10x |
| audit-logging | 1.5x | 2x | 3x |

---

## Resource Requirements

### Redis Capacity

```typescript
function calculateRedisCapacity(queueMetrics: QueueMetrics): RedisCapacity {
  const avgJobSizeKB = 50; // Typical job payload size
  const peakBacklog = queueMetrics.peakRPS * queueMetrics.avgProcessingTime;
  const dailyGrowth = queueMetrics.avgRPS * 86400 * avgJobSizeKB / 1024; // MB/day

  return {
    storage: {
      current: peakBacklog * avgJobSizeKB / 1024, // MB
      projected: dailyGrowth * 30, // 30 day retention
      safety: peakBacklog * avgJobSizeKB / 1024 * 2 // 2x buffer
    },
    memory: {
      workingSet: peakBacklog * avgJobSizeKB / 1024 * 0.5, // Compressed
      overhead: 1024 // MB base overhead
    },
    connections: {
      workers: queueMetrics.workerCount * 2, // Command + Subscribe
      max: 500 // Redis connection limit
    }
  };
}
```

### Worker Capacity

```typescript
function calculateWorkerCapacity(queueMetrics: QueueMetrics): WorkerCapacity {
  const jobsPerWorker = queueMetrics.workerConcurrency;
  const processingTime = queueMetrics.avgProcessingTime; // ms

  const maxThroughput = (1000 / processingTime) * jobsPerWorker; // jobs/sec

  const workersNeeded = Math.ceil(queueMetrics.peakRPS / maxThroughput);

  return {
    workerCount: workersNeeded,
    cpuCores: workersNeeded * 2, // 2 cores per worker
    memoryGB: workersNeeded * 2, // 2GB per worker
    replicas: {
      min: Math.max(2, Math.floor(workersNeeded / 2)),
      max: workersNeeded * 2
    }
  };
}
```

---

## Scaling Triggers

### Auto-Scaling Rules

| Queue | Scale Up Trigger | Scale Down Trigger | Cooldown |
|-------|-----------------|-------------------|----------|
| otp-fastlane | backlog > 500 | backlog < 50 | 60s |
| sms-delivery | backlog > 1000 | backlog < 100 | 120s |
| email-delivery | backlog > 1000 | backlog < 100 | 120s |
| webhook-processing | backlog > 500 | backlog < 50 | 180s |
| audit-logging | backlog > 2000 | backlog < 200 | 300s |

### Capacity Alerts

| Alert Level | Condition | Action |
|-------------|-----------|--------|
| GREEN | < 50% capacity | Normal operation |
| YELLOW | 50-70% capacity | Monitor, prepare to scale |
| ORANGE | 70-85% capacity | Scale up |
| RED | 85-95% capacity | Emergency scale, alert |
| CRITICAL | > 95% capacity | Throttle, incident |

---

## Provider Rate Limit Planning

### Capacity vs Rate Limits

| Provider | Rate Limit | Safe Limit | Headroom |
|----------|------------|------------|----------|
| Twilio | 100/s | 80/s | 20% |
| SendGrid | 100/s | 75/s | 25% |
| Webhooks | 50/s | 40/s | 20% |

### Provider Capacity Planning

```typescript
function calculateProviderCapacity(
  providerRateLimit: number,
  targetUtilization: number,
  queueRPS: number
): ProviderCapacity {
  const safeLimit = providerRateLimit * targetUtilization;
  const queueCapacity = safeLimit * 0.8; // 80% of safe limit for buffer

  return {
    maxQueueRPS: queueCapacity,
    requiresBackpressure: queueRPS > queueCapacity,
    providerBuffer: safeLimit - queueRPS
  };
}
```

---

## Cost Optimization

### Resource Cost Model

| Resource | Unit Cost | Monthly Cost @ Scale |
|----------|-----------|---------------------|
| Redis (1GB) | $0.05/hr | ~$36/month |
| Worker (2CPU/2GB) | $0.10/hr | ~$72/month |
| Database (write unit) | $0.01/10k writes | ~$50/month |

### Optimization Strategies

1. **Batch processing**: Combine small jobs into batches
2. **Off-peak scheduling**: Move non-critical work to off-peak
3. **Compression**: Enable Redis data compression
4. **TTL optimization**: Reduce retention where possible

---

## Capacity Testing

### Load Test Scenarios

| Test | Target Load | Duration | Success Criteria |
|------|-------------|----------|------------------|
| Baseline | 1x current | 1 hour | p99 < SLA |
| Peak | 2x current | 30 min | No failures |
| Stress | 5x current | 15 min | Graceful degradation |
| Soak | 1.5x current | 24 hours | Stable |

### Test Results (Latest: April 2026)

| Queue | Baseline | Peak | Stress | Passed |
|-------|----------|------|--------|--------|
| otp-fastlane | 45ms | 180ms | 450ms | Yes |
| sms-delivery | 150ms | 400ms | 800ms | Yes |
| email-delivery | 250ms | 600ms | 1.2s | Yes |
| webhook-processing | 100ms | 250ms | 500ms | Yes |

---

## Future Capacity Needs

### 12-Month Projections

| Queue | Expected RPS | Worker Count | Redis Storage |
|-------|-------------|--------------|---------------|
| otp-fastlane | 200 | 12 | 8GB |
| sms-delivery | 75 | 8 | 4GB |
| email-delivery | 40 | 6 | 3GB |
| webhook-processing | 40 | 6 | 2GB |
| audit-logging | 10 | 4 | 1GB |

### Infrastructure Investment

- Redis cluster: Scale to 3 nodes (currently 2)
- Worker nodes: Add 10 additional capacity
- Provider quotas: Negotiate increased rate limits

---

## Monitoring

| Metric | Description | Dashboard |
|--------|-------------|-----------|
| `uicp.capacity.utilization` | Overall capacity % | Capacity Overview |
| `uicp.capacity.headroom` | Available capacity | Capacity Overview |
| `uicp.scaling.events` | Auto-scale events | Scaling History |
| `uicp.cost.operations` | Operational cost | Cost Analysis |

---

## Related Documents

- `09-queues/queue-overview.md`
- `09-queues/queue-topology.md`
- `09-queues/worker-concurrency.md`
- `09-queues/provider-queues.md`
- `07-deployment/scaling-strategy.md`
- `08-monitoring/capacity-dashboards.md`
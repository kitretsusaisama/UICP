# Worker Concurrency

## Metadata
```yaml
title: Worker Concurrency
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
  - queue-priorities.md
related-docs:
  - 07-deployment/scaling-strategy.md
  - 16-failure-models/concurrency-bottlenecks.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
  - webhook-processing
  - audit-logging
related-services:
  - BullMQ worker
  - Redis cluster
  - Provider API clients
related-providers:
  - Twilio (SMS)
  - SendGrid (Email)
  - External webhook endpoints
related-runtime-states:
  - CONCURRENT_PROCESSING
  - CONCURRENCY_LIMITED
  - CONCURRENCY_STARVED
  - RATE_LIMITED
related-threat-models:
  - Provider rate limit exhaustion
  - Connection pool exhaustion
  - Resource starvation via high concurrency
```

---

## Overview

Worker concurrency determines how many jobs a single worker can process simultaneously. Proper concurrency settings balance throughput, resource utilization, and external API rate limits. UICP implements per-queue concurrency limits with dynamic adjustment capabilities.

---

## Concurrency Configuration

### Default Settings

| Queue | Max Concurrent | Reason |
|-------|---------------|--------|
| otp-fastlane | 50 | Stateless, low latency |
| sms-delivery | 20 | Twilio rate limits |
| email-delivery | 10 | SendGrid rate limits |
| webhook-processing | 5 | External system tolerance |
| audit-logging | 5 | Database write capacity |

### Concurrency Formulas

```typescript
function calculateOptimalConcurrency(queue: Queue): number {
  const providerRateLimit = getProviderRateLimit(queue.provider);
  const avgProcessingTime = getAverageProcessingTime(queue);
  const workerMemoryMB = 512;

  // Rule: Don't exceed provider rate limit
  // Rule: Processing time should be 80% of available time
  const optimal = Math.min(
    providerRateLimit / avgProcessingTime * 0.8,
    workerMemoryMB / 50 // ~50MB per concurrent job
  );

  return Math.round(optimal);
}
```

---

## Implementation

### BullMQ Concurrency Setting

```typescript
const worker = new Worker('queue-name', async (job) => {
  await processJob(job.data);
}, {
  connection: redisConnection,
  concurrency: 20, // Max concurrent jobs
  lockDuration: 30000, // Job lock timeout
  lockRenewTime: 5000 // Renew lock every 5s
});
```

### Dynamic Concurrency Adjustment

```typescript
class DynamicConcurrencyManager {
  private baseConcurrency: number;
  private currentConcurrency: number;
  private minConcurrency: number;
  private maxConcurrency: number;

  async adjustConcurrency(metrics: QueueMetrics): Promise<void> {
    const errorRate = metrics.failed / metrics.completed;
    const latencyP99 = metrics.latencyP99;

    if (errorRate > 0.1) {
      // High error rate - reduce concurrency
      this.currentConcurrency = Math.max(
        this.minConcurrency,
        this.currentConcurrency * 0.8
      );
    } else if (latencyP99 < 1000 && errorRate < 0.01) {
      // Low latency, low errors - increase concurrency
      this.currentConcurrency = Math.min(
        this.maxConcurrency,
        this.currentConcurrency * 1.2
      );
    }

    await this.updateWorkerConcurrency(this.currentConcurrency);
  }
}
```

---

## Resource Management

### Memory Per Concurrent Job

| Queue | Est. Memory | Notes |
|-------|-------------|-------|
| otp-fastlane | 30 MB | Lightweight |
| sms-delivery | 45 MB | Provider SDK |
| email-delivery | 50 MB | Email templates |
| webhook-processing | 60 MB | Response parsing |
| audit-logging | 40 MB | JSON serialization |

### Connection Pool Sizing

```typescript
const poolConfig = {
  max: 20, // Max connections per worker
  min: 5,  // Minimum idle connections
  acquire: 30000, // Max acquire time
  idle: 10000, // Idle timeout
  eviction: 60000 // Run eviction every
};

// Per worker connection requirements
// otp-fastlane: 50 concurrent = 50 connections
// sms-delivery: 20 concurrent = 20 connections
// email-delivery: 10 concurrent = 10 connections
```

---

## Rate Limit Handling

### Provider Rate Limits

| Provider | Requests/Second | Burst | Backoff |
|----------|----------------|-------|----------|
| Twilio | 100 | 200 | Exponential |
| SendGrid | 100 | 150 | Exponential |
| Webhook (outbound) | 50 | 100 | Linear |

### Rate Limit Middleware

```typescript
async function withRateLimit<T>(
  provider: Provider,
  operation: () => Promise<T>
): Promise<T> {
  const semaphore = provider.getSemaphore();

  await semaphore.acquire();

  try {
    return await operation();
  } finally {
    setTimeout(() => semaphore.release(), 1000 / provider.rateLimit);
  }
}
```

---

## Scaling Workers

### Horizontal Scaling Rules

```typescript
function calculateWorkerCount(queueDepth: number, avgProcessingTime: number): number {
  const targetProcessingRate = 100; // jobs per second
  const workersNeeded = Math.ceil(
    queueDepth * avgProcessingTime / 1000 / targetProcessingRate
  );

  return Math.min(Math.max(workersNeeded, 2), 100); // Min 2, Max 100
}
```

### Auto-Scaling Configuration

```yaml
# Kubernetes HPA configuration
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: worker-otp-fastlane
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: worker-otp-fastlane
  minReplicas: 2
  maxReplicas: 50
  metrics:
  - type: QueueDepth
    queue: otp-fastlane
    target: "100" # Scale when depth > 100
```

---

## Monitoring

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `uicp.worker.concurrency.active` | Active concurrent jobs | > 90% of limit |
| `uicp.worker.concurrency.waiting` | Jobs waiting for slot | > 10 |
| `uicp.worker.memory.usage` | Worker memory usage | > 80% |
| `uicp.worker.connection.pool` | Connection pool usage | > 90% |

---

## Related Documents

- `09-queues/queue-overview.md`
- `09-queues/queue-topology.md`
- `07-deployment/scaling-strategy.md`
- `16-failure-models/concurrency-bottlenecks.md`
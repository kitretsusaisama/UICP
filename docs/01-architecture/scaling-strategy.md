# Scaling Strategy

## Metadata
```yaml
title: Scaling Strategy
domain: infrastructure
owner: Infrastructure Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - distributed-runtime.md
  - multi-region-strategy.md
related-docs:
  - runtime-summary.md
  - queue-first-design.md
```

---

## Overview

UICP scales horizontally to handle varying load. Auto-scaling policies adjust capacity based on demand metrics while maintaining cost efficiency.

---

## Scaling Dimensions

### API Layer Scaling

```typescript
// Horizontal scaling for API nodes
const apiAutoScale = {
  minInstances: 3,
  maxInstances: 50,

  metrics: [
    {
      type: 'cpu',
      target: 70, // Scale up at 70% CPU
      cooldown: 300, // 5 minutes between scales
    },
    {
      type: 'request_count',
      target: 1000, // 1000 requests per instance
      cooldown: 120,
    },
    {
      type: 'latency',
      target: 500, // Scale up if p99 > 500ms
      cooldown: 180,
    },
  ],
};
```

### Queue Worker Scaling

```typescript
// Worker pool scaling by queue depth
const workerAutoScale = {
  queues: {
    'email-delivery': {
      minWorkers: 5,
      maxWorkers: 50,
      scaleThreshold: 100, // Jobs waiting
      workersPerThreshold: 2,
    },
    'sms-delivery': {
      minWorkers: 3,
      maxWorkers: 30,
      scaleThreshold: 50,
      workersPerThreshold: 1,
    },
    'otp-fastlane': {
      minWorkers: 5,
      maxWorkers: 20,
      scaleThreshold: 10, // More sensitive for OTP
      workersPerThreshold: 2,
    },
  },
};
```

---

## Scaling Strategies

### Reactive Scaling

```typescript
class AutoScaler {
  async evaluateScaling(): Promise<void> {
    const metrics = await this.metricsProvider.getCurrentMetrics();

    for (const target of this.scaleTargets) {
      const currentInstances = await this.getCurrentInstances(target.resource);
      const required = this.calculateRequiredInstances(target, metrics);

      if (required > currentInstances) {
        await this.scaleUp(target.resource, required);
      } else if (required < currentInstances * 0.8) {
        await this.scaleDown(target.resource, required);
      }
    }
  }

  calculateRequiredInstances(
    target: ScaleTarget,
    metrics: Metrics
  ): number {
    const cpuMetric = metrics.find(m => m.name === 'cpu' && m.resource === target.resource);
    const targetInstances = Math.ceil(
      (cpuMetric.value / target.config.target) * target.currentInstances
    );

    return Math.min(
      Math.max(target.config.minInstances, targetInstances),
      target.config.maxInstances
    );
  }
}
```

### Predictive Scaling

```typescript
// Scale based on historical patterns
class PredictiveScaler {
  async predictCapacity(hourFromNow: number): Promise<number> {
    // Get historical data for same hour/day
    const history = await this.metrics.getHistorical(
      hourFromNow,
      'request_count'
    );

    // Calculate expected load with growth factor
    const avgRequests = this.calculateAverage(history);
    const growthFactor = await this.growthTracker.getGrowthFactor();

    return Math.ceil(avgRequests * growthFactor);
  }

  async preScale(): Promise<void> {
    const predicted = await this.predictCapacity(1);

    if (predicted > await this.getCurrentCapacity()) {
      await this.scaleUp('api', predicted);
    }
  }
}
```

---

## Database Scaling

### Read Replicas

```typescript
// Add read replicas for query load
const readReplicaConfig = {
  primary: 'us-east-1-mysql-primary',
  replicas: [
    { name: 'us-east-1-read-1', region: 'us-east-1' },
    { name: 'us-east-1-read-2', region: 'us-east-1' },
    { name: 'eu-west-1-read-1', region: 'eu-west-1' },
  ],

  // Auto-scale replicas based on query load
  scalePolicy: {
    metric: 'connections',
    threshold: 80, // Scale at 80% max connections
    maxReplicas: 10,
  },
};
```

### Connection Pooling

```typescript
// Optimize connection usage
const poolConfig = {
  // Read operations use replicas
  read: {
    connectionLimit: 100,
    acquireTimeout: 10000,
    idleTimeout: 30000,
  },

  // Write operations use primary
  write: {
    connectionLimit: 50,
    acquireTimeout: 5000,
    idleTimeout: 10000,
  },
};
```

---

## Cache Scaling

### Redis Cluster Scaling

```typescript
// Scale Redis for session/rate limit storage
const redisScaling = {
  shards: {
    initial: 3,
    max: 20,

    // Auto-scale based on memory
    memoryThreshold: 70, // Add shard at 70% memory
  },

  replicas: {
    perShard: 2, // Each shard has 2 replicas
  },
};
```

---

## Cost Optimization

### Spot Instances

```typescript
// Use spot for stateless workloads
const spotConfig = {
  apiNodes: {
    instanceTypes: ['m5.xlarge', 'm5.2xlarge', 'm5.4xlarge'],
    spotPercentage: 70, // 70% spot, 30% on-demand
    InterruptionBehavior: 'terminate',
  },

  workers: {
    instanceTypes: ['c5.xlarge', 'c5.2xlarge'],
    spotPercentage: 90,
    interruptionTolerance: 'medium', // Can tolerate some interruption
  },
};
```

### Right-Sizing

```typescript
// Reduce over-provisioned resources
class RightSizer {
  async analyze(): Promise<RightSizeRecommendation[]> {
    const resources = await this.getAllResources();

    const recommendations = [];
    for (const resource of resources) {
      const utilization = await this.getUtilization(resource);

      if (utilization < 30) {
        recommendations.push({
          resource: resource.id,
          currentSize: resource.size,
          recommendedSize: this.calculateRecommendedSize(utilization),
          savings: this.calculateSavings(resource, this.calculateRecommendedSize(utilization)),
        });
      }
    }

    return recommendations;
  }
}
```

---

## Related Documents

- `distributed-runtime.md`
- `multi-region-strategy.md`
- `runtime-summary.md`
- `queue-first-design.md`
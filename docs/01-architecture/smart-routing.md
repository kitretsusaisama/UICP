# Smart Routing

## Metadata
```yaml
title: Smart Routing
domain: integration
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: CRITICAL
tenant-impact: LOW
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - communication-fabric.md
  - multi-region-strategy.md
related-docs:
  - provider-scoring.md
  - provider-outages.md
related-queues:
  - all-provider-queues
related-services:
  - provider-router
  - provider-router-worker
related-providers:
  - all-providers
```

---

## Overview

Smart routing dynamically selects the best provider for each request based on health, cost, performance, and tenant preferences. This maximizes delivery success while minimizing costs.

---

## Routing Criteria

### Provider Scoring

```typescript
interface ProviderScore {
  provider: ProviderType;
  health: number;      // 0-100, provider availability
  cost: number;       // 0-100, inverse of cost (higher = cheaper)
  performance: number; // 0-100, latency/throughput
  reliability: number; // 0-100, historical success rate

  total: number;      // Weighted sum
}

function calculateScore(provider: ProviderType, request: ProviderRequest): ProviderScore {
  const health = getHealthScore(provider);
  const cost = getCostScore(provider, request);
  const performance = getPerformanceScore(provider, request.channel);
  const reliability = getReliabilityScore(provider);

  return {
    provider,
    health,
    cost,
    performance,
    reliability,
    total: (health * 0.3) + (cost * 0.2) + (performance * 0.3) + (reliability * 0.2),
  };
}
```

### Selection Algorithm

```typescript
async function selectBestProvider(
  channel: Channel,
  tenantId: TenantId,
  request: ProviderRequest
): Promise<ProviderType> {
  // 1. Get available providers for channel
  const providers = getProvidersForChannel(channel);

  // 2. Filter out unhealthy providers
  const healthy = providers.filter(p => getHealthScore(p) > 50);

  // 3. Calculate scores
  const scored = healthy.map(p => ({
    provider: p,
    score: calculateScore(p, request),
  }));

  // 4. Sort by total score
  scored.sort((a, b) => b.score.total - a.score.total);

  // 5. Return best provider
  return scored[0].provider;
}
```

---

## Dynamic Health Monitoring

### Health Checks

```typescript
class ProviderHealthMonitor {
  async checkProviderHealth(provider: ProviderType): Promise<ProviderHealth> {
    try {
      const start = Date.now();
      await provider.healthCheck();
      const latency = Date.now() - start;

      return {
        provider,
        healthy: true,
        latency,
        timestamp: new Date(),
      };
    } catch (error) {
      return {
        provider,
        healthy: false,
        error: error.message,
        timestamp: new Date(),
      };
    }
  }

  async updateHealthScores(): Promise<void> {
    const providers = getAllProviders();

    for (const provider of providers) {
      const health = await this.checkProviderHealth(provider);
      await this.redis.hset('provider:health', provider, JSON.stringify(health));
    }
  }
}
```

### Continuous Scoring

```typescript
class ScoreTracker {
  async recordDeliveryAttempt(
    provider: ProviderType,
    channel: Channel,
    success: boolean,
    latency: number
  ): Promise<void> {
    const key = `provider:stats:${provider}:${channel}`;

    // Increment counters
    await this.redis.hincrby(key, 'total', 1);
    if (success) {
      await this.redis.hincrby(key, 'success', 1);
      await this.redis.hincrbyfloat(key, 'totalLatency', latency);
    } else {
      await this.redis.hincrby(key, 'failure', 1);
    }

    // Expire old stats
    await this.redis.expire(key, 86400);
  }

  async getReliabilityScore(provider: ProviderType, channel: Channel): Promise<number> {
    const stats = await this.redis.hgetall(`provider:stats:${provider}:${channel}`);
    const total = parseInt(stats.total || '0');
    const success = parseInt(stats.success || '0');

    if (total === 0) return 100; // Default to perfect if no data
    return (success / total) * 100;
  }
}
```

---

## Tenant Preferences

### Custom Routing Rules

```typescript
interface TenantRoutingPreferences {
  preferredProviders: ProviderType[];  // Priority order
  excludedProviders: ProviderType[];  // Never use these
  fallbackEnabled: boolean;            // Try next on failure
  maxRetries: number;                  // Retries before giving up
}

async function applyTenantPreferences(
  providers: ProviderType[],
  tenant: Tenant
): Promise<ProviderType[]> {
  const prefs = tenant.settings.routingPreferences;

  // Remove excluded
  let filtered = providers.filter(p => !prefs.excludedProviders.includes(p));

  // Prioritize preferred
  filtered.sort((a, b) => {
    const aIdx = prefs.preferredProviders.indexOf(a);
    const bIdx = prefs.preferredProviders.indexOf(b);
    return aIdx - bIdx;
  });

  return filtered;
}
```

---

## Geographic Routing

### Region-Based Selection

```typescript
interface GeoRoutingConfig {
  region: string;
  providers: ProviderType[];
  latencyWeight: number;
}

async function selectProviderByRegion(
  channel: Channel,
  tenantRegion: string,
  request: ProviderRequest
): Promise<ProviderType> {
  // 1. Get providers available in region
  const regionConfig = getRegionConfig(tenantRegion);
  const regionProviders = regionConfig.providers;

  // 2. Score by latency for region
  const scored = regionProviders.map(p => ({
    provider: p,
    score: calculateScore(p, request),
  }));

  // 3. Select best
  scored.sort((a, b) => b.score.total - a.score.total);
  return scored[0].provider;
}
```

---

## Cost-Based Routing

### Price Optimization

```typescript
const PROVIDER_RATES = {
  email: {
    sendgrid: { perThousand: 1.00 },
    aws_ses: { perThousand: 0.10 },
    mailgun: { perThousand: 0.80 },
  },
  sms: {
    twilio: { perMessage: 0.0075 },
    aws_sns: { perMessage: 0.0060 },
  },
};

function getCheapestProvider(channel: Channel, recipients: string[]): ProviderType {
  const rates = PROVIDER_RATES[channel];
  const count = recipients.length;

  const costs = Object.entries(rates).map(([provider, rate]) => ({
    provider,
    cost: rate.perThousand * (count / 1000),
  }));

  costs.sort((a, b) => a.cost - b.cost);
  return costs[0].provider as ProviderType;
}
```

---

## Related Documents

- `communication-fabric.md`
- `multi-region-strategy.md`
- `18-smart-tuning/provider-scoring.md`
- `16-failure-models/provider-outages.md`
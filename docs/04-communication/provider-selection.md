# Provider Selection

## Metadata
```yaml
title: Provider Selection
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: LOW
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - communication-overview.md
  - provider-runtime.md
  - provider-health.md
related-docs:
  - delivery-intelligence.md
  - fallback-policies.md
  - regional-routing.md
related-queues:
  - email-delivery
  - sms-delivery
related-services:
  - ProviderRouter
  - ProviderHealthMonitor
  - CostOptimizer
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - provider_healthy
  - provider_degraded
  - provider_failed
  - provider_quota_exhausted
  - selection_in_progress
  - selection_complete
related-threat-models:
  - Provider lock-in
  - Cost optimization bypass
```

---

## Overview

Provider Selection determines the optimal provider for each message based on health, cost, regional fit, and tenant preferences. The algorithm continuously adapts to provider performance and tenant configuration.

---

## Selection Algorithm

### Phase 1: Candidate Filtering

```
Input: Message context (region, channel, tenant)
Output: Eligible providers list
Filters applied:
  1. Channel support (email vs SMS)
  2. Region availability
  3. Tenant whitelist/blacklist
  4. Minimum health threshold
```

### Phase 2: Scoring

Each eligible provider receives a composite score:

```typescript
interface ProviderScore {
  providerId: string;
  components: {
    health: number;        // 0-40 weight
    cost: number;          // 0-30 weight
    latency: number;      // 0-20 weight
    quota: number;        // 0-10 weight
  };
  total: number;
}
```

### Phase 3: Selection

```
Selection logic:
1. If primary provider healthy → select primary
2. If primary degraded → compare scores, select highest
3. If all degraded → use fallback chain
4. If no eligible providers → queue for retry
```

---

## Scoring Components

### Health Score (40%)

Based on delivery success rate and error rate:

```
Health = (delivered / total) × 100
Adjusted by: error_rate_penalty
```

Thresholds:
- Healthy: >= 95%
- Degraded: 85-94%
- Failed: < 85%

### Cost Score (30%)

Normalized cost comparison:

```
Cost = 1 - (provider_cost / max_provider_cost)
```

Provider costs (per 1000 messages):
- SES: $0.10
- Resend: $0.12
- Maileroo: $0.08
- Msg91: $0.05

### Latency Score (20%)

Based on average provider response time:

```
Latency = 1 - (avg_latency / max_acceptable_latency)
Max acceptable: 5000ms
```

### Quota Score (10%)

Available quota headroom:

```
Quota = remaining_quota / total_quota
```

---

## Tenant Preferences

### Primary Provider

Tenants can specify a preferred provider:

```typescript
interface TenantConfig {
  preferredProvider?: string;
  fallbackEnabled: boolean;
  maxCostMultiplier: number;
  regionPreference?: string;
}
```

### Provider Lock-in Prevention

The system enforces rotation to prevent single-provider reliance:

- Maximum 80% traffic to any one provider
- Automatic rotation every 7 days
- Manual override available

---

## Regional Routing

### Region Detection

Messages are tagged with region based on:
- Recipient domain TLD
- Tenant configured region
- GeoIP lookup of recipient

### Regional Scoring

```
Regional match bonus: +15 points
Partial match: +5 points
No match: 0 points
```

---

## Fallback Behavior

When primary provider fails:

```
1. Mark provider as degraded
2. Select next-best available provider
3. Increment fallback counter
4. Log selection reason
5. Continue monitoring original provider
```

---

## Observability

### Selection Metrics

| Metric | Description |
|--------|-------------|
| selection_total | Total selection events |
| selection_by_provider | Breakdown by provider |
| fallback_triggered | Fallback usage count |
| selection_latency_ms | Algorithm execution time |

---

## Related Documents

- `04-communication/communication-overview.md`
- `04-communication/provider-runtime.md`
- `04-communication/fallback-policies.md`
- `04-communication/regional-routing.md`
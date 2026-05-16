# Provider Health

## Metadata
```yaml
title: Provider Health
domain: communication
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: LOW
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: daily
last-reviewed: 2026-05-16
depends-on:
  - provider-runtime.md
  - delivery-intelligence.md
related-docs:
  - provider-selection.md
  - fallback-policies.md
  - provider-failure-handling.md
related-queues:
  - health-check
related-services:
  - ProviderHealthMonitor
  - HealthAggregator
  - AlertManager
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - health_check_init
  - health_check_running
  - provider_healthy
  - provider_degraded
  - provider_unhealthy
  - provider_unknown
related-threat-models:
  - Health check spoofing
  - False positives
```

---

## Overview

Provider Health continuously monitors the operational status of all communication providers. The system aggregates multiple data sources to determine real-time health status and triggers automated remediation when issues are detected.

---

## Health Indicators

### Primary Metrics

| Metric | Weight | Source |
|--------|--------|--------|
| Delivery success rate | 40% | Webhooks |
| API latency (p95) | 25% | API monitoring |
| Error rate | 20% | API responses |
| Quota availability | 15% | Provider API |

### Health Score Calculation

```typescript
function calculateHealthScore(metrics: ProviderMetrics): number {
  const deliveryScore = metrics.deliveryRate * 0.4;
  const latencyScore = calculateLatencyScore(metrics.p95Latency) * 0.25;
  const errorScore = (1 - metrics.errorRate) * 0.2;
  const quotaScore = metrics.quotaRemaining * 0.15;

  const total = deliveryScore + latencyScore + errorScore + quotaScore;

  // Normalize to 0-100
  return Math.round(total * 100);
}

function calculateLatencyScore(p95: number): number {
  if (p95 < 500) return 1;
  if (p95 < 1000) return 0.9;
  if (p95 < 2000) return 0.7;
  if (p95 < 5000) return 0.5;
  return 0;
}
```

---

## Health States

### State Definitions

| State | Score Range | Action |
|-------|-------------|--------|
| HEALTHY | 80-100 | Normal operation |
| DEGRADED | 50-79 | Increased monitoring |
| UNHEALTHY | 0-49 | Auto-failover |

### State Transitions

```
HEALTHY → DEGRADED: Score < 80 for 5 minutes
DEGRADED → HEALTHY: Score >= 80 for 10 minutes
DEGRADED → UNHEALTHY: Score < 50 for 3 minutes
UNHEALTHY → DEGRADED: Score >= 50 for 15 minutes
```

---

## Monitoring Strategy

### Active Health Checks

```typescript
async function performHealthCheck(provider: string): Promise<HealthResult> {
  const start = Date.now();

  try {
    await provider.validateCredentials();
    const latency = Date.now() - start;

    return {
      provider,
      status: 'healthy',
      latency,
      checkedAt: new Date(),
      details: await gatherMetrics(provider)
    };
  } catch (error) {
    return {
      provider,
      status: 'unhealthy',
      error: error.message,
      checkedAt: new Date()
    };
  }
}
```

### Check Frequency

| Provider | Interval | Timeout |
|----------|----------|---------|
| SES | 30s | 10s |
| Resend | 30s | 10s |
| Maileroo | 60s | 15s |
| Msg91 | 30s | 10s |

---

## Alert Integration

### Alert Conditions

| Condition | Severity | Notification |
|-----------|----------|--------------|
| Provider unhealthy | P1 | Immediate |
| Provider degraded | P2 | 15 min |
| Latency spike | P3 | 1 hour |
| Quota < 20% | P2 | 1 hour |
| All providers unhealthy | P1 | Immediate |

### Alert Channels

- P1: Phone, Slack, Email
- P2: Slack, Email
- P3: Email only

---

## Dashboard Integration

### Real-Time Dashboard

```typescript
interface HealthDashboardData {
  providers: {
    id: string;
    status: 'healthy' | 'degraded' | 'unhealthy';
    score: number;
    metrics: ProviderMetrics;
    lastChecked: Date;
  }[];
  alerts: ActiveAlert[];
  trends: HealthTrend[];
}
```

---

## Automatic Remediation

### Remediation Actions

| State | Action |
|-------|--------|
| Unhealthy | Trigger fallback |
| Degraded | Increase monitoring |
| Quota low | Alert finance |
| Error spike | Pause new sends |

---

## Related Documents

- `04-communication/provider-runtime.md`
- `04-communication/provider-selection.md`
- `04-communication/fallback-policies.md`
# Provider Scoring

## Metadata
```yaml
title: Provider Scoring
domain: smart-tuning
owner: Platform Team
criticality: MEDIUM
runtime-impact: MEDIUM
security-impact: NONE
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - 04-communication/provider-runtime
  - 02-runtime/fallback-runtime
related-docs:
  - 18-smart-tuning/retry-tuning.md
  - 18-smart-tuning/fallback-tuning.md
related-queues: []
related-services:
  - Provider Router
  - Score Aggregator
related-providers:
  - All providers
```

---

## Overview

Provider scoring enables dynamic provider selection based on real-time performance metrics rather than static configurations. This adaptive mechanism ensures that traffic is routed to the most reliable and performant providers at any given moment, creating a self-healing delivery system that responds to provider degradation without manual intervention.

The scoring system operates as a continuous feedback loop, collecting metrics from every delivery attempt and adjusting provider weights accordingly. This approach transforms provider selection from a configuration task into an intelligent, data-driven process that improves over time as more delivery data accumulates.

---

## Scoring Factors

The scoring algorithm considers four primary factors, each weighted according to its impact on delivery success:

| Factor | Weight | Description |
|--------|--------|-------------|
| Delivery Rate | 40% | Percentage of successful deliveries |
| Latency | 30% | Average response time from provider |
| Error Rate | 20% | Percentage of failed requests |
| Quota Remaining | 10% | Available capacity relative to total |

These weights can be adjusted per tenant or use case, allowing different optimization priorities. For high-volume transactional flows, latency might be weighted more heavily, while reliability-critical communications might prioritize delivery rate above all else.

---

## Score Calculation

```
Score = (deliveryRate * 0.4) + (latencyScore * 0.3) + (errorScore * 0.2) + (quotaScore * 0.1)

Where:
- deliveryRate = successful / total
- latencyScore = 1 - (avgLatency / maxLatency)
- errorScore = 1 - (errors / total)
- quotaScore = quotaRemaining / totalQuota
```

The score calculation produces a normalized value between 0 and 100, where higher scores indicate better provider performance. Providers with scores below 20 are automatically flagged for review, while those below 10 trigger automatic fallback to alternative providers.

---

## Adjustment Triggers

Immediate score adjustments occur based on specific events:

- Delivery failure: -5 points
- Latency exceeding 5 seconds: -3 points
- Timeout: -10 points
- Successful delivery: +1 point (capped at 100)

These triggers enable rapid response to acute provider issues. A provider experiencing a temporary outage will see its score drop quickly, causing traffic to shift to healthier alternatives within seconds rather than minutes.

---

## Score Decay

Scores decay at 1% per hour when no recent metrics are available, preventing stale scores from influencing routing decisions. This decay ensures that providers are given fresh opportunities when their performance improves, rather than being penalized indefinitely for past issues.

---

## Related Documents

- `18-smart-tuning/retry-tuning.md`
- `18-smart-tuning/fallback-tuning.md`
- `04-communication/provider-runtime.md`
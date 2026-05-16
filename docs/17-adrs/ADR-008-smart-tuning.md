# ADR-008: Smart Provider Tuning

## Status
Accepted

## Context
UICP integrates with multiple email/SMS providers (Ses, Resend, Maileroo, MSG91) with varying performance characteristics. Need intelligent provider selection to optimize delivery rates, latency, and cost.

## Decision
Implement provider scoring system with:
- **Metrics collection**: Track delivery success rate, latency, bounce rate per provider
- **Score calculation**: Weighted scoring (reliability 40%, latency 30%, cost 20%, features 10%)
- **Automatic failover**: Fallback to next-highest scorer on failure
- **Manual override**: Allow operators to pin provider preference
- **A/B testing**: Route % of traffic to test new providers

## Consequences
### Positive
- Optimized delivery rates through data-driven selection
- Reduced latency by preferring faster providers
- Cost optimization through provider comparison
- Graceful degradation via automatic failover

### Negative
- Complexity in scoring algorithm tuning
- Initial data collection period needed
- Potential for thrashing if scores fluctuate

## Metadata
```yaml
title: Smart Provider Tuning
domain: provider-optimization
owner: Platform Team
criticality: medium
runtime-impact: medium
security-impact: low
queue-impact: low
provider-impact: high
tenant-impact: low
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - ADR-004: Provider Abstraction
  - ADR-003: Queue-First Runtime
related-docs:
  - docs/18-smart-tuning/provider-scoring.md
  - docs/04-communication/provider-selection.md
```

## Related ADRs
- ADR-004: Provider Abstraction
- ADR-003: Queue-First Runtime
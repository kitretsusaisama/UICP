# Regional Routing

## Metadata
```yaml
title: Regional Routing
domain: smart-tuning
owner: Platform Team
criticality: MEDIUM
runtime-impact: HIGH
security-impact: NONE
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 02-runtime/provider-selection
  - 18-smart-tuning/provider-scoring.md
  - 18-smart-tuning/fallback-tuning.md
related-docs:
  - 18-smart-tuning/fallback-tuning.md
  - 18-smart-tuning/worker-concurrency.md
  - 04-communication/provider-runtime.md
related-queues: []
related-services:
  - Regional Router
  - Geo-Location Service
  - Provider Regional Endpoints
related-providers:
  - AWS SES
  - Resend
  - Maileroo
  - Msg91
```

---

## Overview

Regional routing optimizes delivery by selecting providers and endpoints based on recipient geographic location. Different providers have different regional strengths, and routing to geographically proximate endpoints reduces latency while improving deliverability by aligning with regional provider expertise.

The regional routing system maintains up-to-date mapping between geographic regions and provider capabilities, continuously optimizing routes based on real-time performance data from each region. This ensures that messages are always routed through the most effective path for their destination.

---

## Region Mapping Strategy

Geographic regions are mapped to provider endpoints using multiple factors:

**Provider Coverage** determines which providers serve each region. Coverage data is maintained both from provider documentation and from observed delivery success rates to different geographic areas. Providers with explicit regional presence receive priority for traffic to those regions.

**Latency Optimization** routes traffic to the lowest-latency endpoint for each region. The system continuously measures response times to each provider endpoint from multiple geographic vantage points, selecting the optimal path based on real measurements rather than static configuration.

**Regulatory Compliance** routes traffic through providers compliant with regional data protection requirements. Messages to EU recipients are routed through providers with GDPR-compliant data handling, while messages to other regions use providers with appropriate local compliance.

---

## Region Configuration

Regions are defined with configurable boundaries and routing rules:

| Region | Primary Provider | Fallback Provider | Compliance |
|--------|------------------|-------------------|------------|
| North America | AWS SES | Resend | CCPA |
| European Union | Resend | AWS SES | GDPR |
| Asia Pacific | Msg91 | Maileroo | Local laws |
| South America | Maileroo | AWS SES | LGPD |
| Middle East | Maileroo | Msg91 | Local laws |

Region configuration is tenant-adjustable, allowing organizations with specific compliance requirements to override default mappings. Premium tenants can define custom regions with specific provider requirements.

---

## Dynamic Region Selection

Region selection adapts based on real-time conditions:

**Performance-Based Selection** evaluates delivery success rates and latency within each region, automatically routing traffic away from underperforming providers even when configuration specifies a particular provider.

**Capacity-Based Routing** monitors provider capacity in each region and distributes load to prevent any single provider from becoming overloaded. When regional capacity thresholds are exceeded, traffic automatically shifts to alternative regional endpoints.

**Failure Isolation** prevents regional failures from affecting traffic to other regions. If a provider fails in Europe but remains healthy in North America, traffic to Europe automatically shifts to fallback while North America traffic continues normally.

---

## Multi-Region Deployment

The system supports multi-region deployment for global availability:

**Active-Active Configuration** runs provider connections in multiple geographic regions simultaneously, with automatic failover between regions when regional failures occur. This configuration provides the highest availability but requires coordination to ensure consistent state.

**Active-Passive Configuration** maintains hot standby regions that activate only during primary region failures. This approach reduces operational cost but adds failover latency during regional incidents.

**Hybrid Configuration** runs active connections in multiple primary regions with selective fallback to central infrastructure, balancing between performance optimization and cost efficiency.

---

## Latency Optimization

Geographic routing directly impacts message delivery latency:

**Endpoint Selection** chooses the lowest-latency provider endpoint for each message based on recipient location. The latency calculation considers network distance, provider processing time, and historical performance.

**Connection Reuse** maintains persistent connections to provider endpoints in each region, avoiding connection establishment latency for high-volume routes. Connection pools are sized per-region based on expected traffic volume.

**Preemptive Routing** routes traffic to regions before recipients interact with messages, preparing delivery infrastructure before acknowledgment is needed. This approach reduces perceived latency for time-sensitive communications.

---

## Related Documents

- `04-communication/provider-runtime.md`
- `18-smart-tuning/fallback-tuning.md`
- `02-runtime/provider-selection.md`
# ADR-009: Regional Routing

## Status
Accepted

## Context
UICP serves tenants across multiple geographic regions. Provider availability, latency, and data sovereignty requirements vary by region. Need intelligent routing based on tenant location and provider coverage.

## Decision
Implement regional routing with:
- **Tenant region assignment**: Tenants pinned to region at creation (US, EU, APAC)
- **Provider regional mapping**: Each provider configured per-region with fallback
- **Latency-based routing**: Select provider with lowest RTT to tenant region
- **Data residency**: Ensure tenant data stays within assigned region
- **Regional failover**: Cross-region fallback only when local providers fail

Provider region matrix:
| Provider | US | EU | APAC |
|----------|----|----|------|
| Ses | Primary | Primary | Backup |
| Resend | Primary | Primary | Backup |
| Maileroo | Backup | Primary | Primary |
| MSG91 | Backup | Backup | Primary |

## Consequences
### Positive
- Lower latency through regional provider selection
- Data sovereignty compliance per region
- Resilience via regional failover
- Provider cost optimization by region

### Negative
- Increased configuration complexity
- Cross-region failover adds latency
- Provider feature parity varies by region

## Metadata
```yaml
title: Regional Routing
domain: geo-routing
owner: Network Team
criticality: high
runtime-impact: high
security-impact: medium
queue-impact: medium
provider-impact: high
tenant-impact: high
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - ADR-004: Provider Abstraction
  - ADR-003: Queue-First Runtime
  - ADR-008: Smart Tuning
related-docs:
  - docs/04-communication/provider-runtime.md
  - docs/01-architecture/distributed-runtime.md
```

## Related ADRs
- ADR-004: Provider Abstraction
- ADR-003: Queue-First Runtime
- ADR-008: Smart Provider Tuning
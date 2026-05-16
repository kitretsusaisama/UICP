```yaml
title: Provider Selection
domain: execution
owner: platform-runtime
criticality: critical
runtime-impact: cross-component
security-impact: medium
queue-impact: low
provider-impact: high
tenant-impact: medium
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - request-lifecycle.md
  - runtime-context-propagation.md
related-docs:
  - request-lifecycle.md
  - retry-runtime.md
  - fallback-runtime.md
related-queues:
  - provider-routing
  - provider-health
related-services:
  - provider-router
  - provider-health-monitor
  - routing-policy-engine
related-providers:
  - all-configured-providers
related-runtime-states:
  - pending
  - routing
  - selected
  - executing
related-threat-models:
  - provider-enumeration
  - routing-manipulation
  - provider-blocking
```

# Provider Selection

Provider selection determines which external provider handles each request based on routing policies, provider availability, performance characteristics, and tenant-specific configurations. This critical runtime component directly impacts request success rates, latency, and cost optimization.

## Selection Criteria

The routing-policy-engine evaluates multiple factors when selecting providers. Capability matching filters providers to those supporting the requested operation type and parameters. Geographic proximity selects providers minimizing network latency to the end user. Cost optimization routes requests to providers offering the best price-performance ratio for the specific operation. Load distribution spreads requests across available providers to prevent concentration on single points.

## Routing Policies

Multiple routing policies serve different operational goals. Round-robin rotation distributes requests evenly across eligible providers. Weighted routing sends proportional traffic based on performance rankings. Least-loaded routing directs requests to providers with the lowest current utilization. Circuit-breaker integration routes around providers exhibiting elevated failure rates. Tenant affinity maintains consistent provider assignments for requests from the same tenant when required.

## Health Integration

The provider-health-monitor continuously evaluates provider availability and performance. Latency thresholds trigger routing adjustments when providers exceed acceptable response times. Error rate monitoring activates fallback routing when providers experience elevated failure rates. Availability checks verify provider connectivity before routing requests. Historical performance data informs routing decisions for predictive optimization.

## Tenant Isolation

Provider selection respects tenant-specific routing requirements. Dedicated provider pools isolate high-value tenants from shared capacity contention. Provider allowlists and blocklists let tenants control which providers handle their requests. Compliance requirements route requests to providers meeting specific certifications or geographic requirements. Cost allocation attributes route requests to track spending against tenant quotas.

## Fallback Coordination

Provider selection integrates with retry-runtime and fallback-runtime mechanisms. Primary provider failure triggers automatic fallback to alternate providers. Retry attempts after failure re-evaluate provider selection to avoid repeatedly failing providers. Provider hysteresis prevents rapid flapping between providers during transient conditions. Selection history informs adaptive retry strategies for improved success rates.
```
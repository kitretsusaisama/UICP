```yaml
title: Throttling Runtime
domain: execution
owner: platform-runtime
criticality: high
runtime-impact: cross-component
security-impact: low
queue-impact: high
provider-impact: high
tenant-impact: medium
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - request-lifecycle.md
  - provider-selection.md
related-docs:
  - request-lifecycle.md
  - provider-selection.md
  - throttling-runtime.md
related-queues:
  - rate-limit-tokens
  - throttling-decisions
related-services:
  - throttling-coordinator
  - rate-limiter
  - quota-manager
  - burst-controller
related-providers:
  - all-configured-providers
related-runtime-states:
  - accepting
  - throttled
  - queued
  - rejected
related-threat-models:
  - throttle-evasion
  - quota-exhaustion-attack
```

# Throttling Runtime

The throttling-runtime enforces rate limits and quota restrictions across all request processing, protecting system stability and ensuring fair resource allocation among tenants while preventing overwhelming downstream providers.

## Rate Limiting

The rate-limiter implements request rate controls at multiple granularities. Per-tenant rate limiting restricts total request rates per tenant. Per-provider rate limiting prevents overwhelming individual providers. Per-endpoint rate limiting controls access to specific API endpoints. Global rate limiting protects overall system capacity.

## Quota Management

The quota-manager tracks and enforces resource quotas. Request quotas limit total requests within time windows. Cost quotas restrict spending on external providers. Compute quotas limit processing resource consumption. Storage quotas control data retention volumes.

## Burst Control

The burst-controller handles traffic spikes within rate limits. Token bucket implementation allows controlled bursts while maintaining average rate limits. Queue-based buffering holds excess requests for later processing when capacity becomes available. Drop strategies determine which requests to reject during extreme load.

## Throttling Responses

Runtime responds to throttle conditions with appropriate actions. Immediate rejection returns error responses for requests exceeding hard limits. Queueing places requests in wait states for processing when capacity becomes available. Backpressure signals upstream systems to reduce sending rates. Retry-after headers inform clients of throttle duration.

## Throttling Analytics

Comprehensive metrics enable throttling optimization. Throttle rate tracking shows how often throttling activates. Quota utilization reveals consumption patterns across tenants. Burst detection identifies traffic patterns causing throttling. Threshold tuning recommendations suggest optimal limit values based on historical data.
```
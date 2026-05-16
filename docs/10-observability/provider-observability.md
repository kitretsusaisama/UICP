# Observability - Provider Observability

## Metadata
```yaml
title: Observability - Provider Observability
domain: observability
owner: Platform Engineering
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: LOW
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - 10-observability/metrics
  - 10-observability/tracing
related-docs:
  - 06-integration/provider-integration
  - 10-observability/operational-alerts
related-queues: []
related-services:
  - provider-adapters
  - circuit-breaker
  - rate-limiter
```

---

## Overview

Provider observability focuses on monitoring external service integrations, including identity providers, credential validation services, and third-party APIs. This document establishes metrics, alerting, and troubleshooting procedures for provider integrations.

---

## Provider Health Metrics

Provider availability is measured through successful request ratio. The `provider.availability` metric reports the percentage of successful requests over trailing windows (1m, 5m, 15m, 1h). Availability below 99.5% triggers warning alerts, below 99% triggers critical alerts.

Provider latency metrics capture response time distributions per provider. The `provider.latency` histogram tracks p50, p75, p90, p95, and p99 percentiles. Providers are classified by latency tier: fast (<200ms p95), moderate (200-500ms p95), slow (>500ms p95). Slow providers may warrant caching or fallback strategies.

Error classification distinguishes provider errors from platform errors. The `provider.errors.client` metric counts errors attributable to provider (4xx responses, invalid data). The `provider.errors.server` metric counts provider service errors (5xx responses, timeouts). Client errors may indicate configuration issues requiring investigation.

---

## Circuit Breaker Monitoring

Circuit breaker state transitions are key provider health indicators. The `circuitbreaker.state` metric reports current state (closed, open, half-open) per provider. State transition frequency alerts on rapid state changes indicating instability.

Circuit breaker opening events are logged with cause, duration, and error context. A high opening rate indicates providers experiencing sustained issues requiring attention. The `circuitbreaker.opening.rate` metric tracks openings per hour per provider.

Half-open state metrics track probe request success rate. Successful probes in half-open state close the circuit, restoring normal operation. Failed probes reopen the circuit. The `circuitbreaker.probes.success.rate` metric should remain above 80% for stable operation.

---

## Rate Limiting Tracking

Provider rate limit status is monitored to prevent throttling. The `provider.rate_limit.remaining` gauge reports remaining quota per provider per time window. Rate limit exhaustion triggers alerts to prevent service disruption.

Rate limit headroom metrics show the gap between current usage and limit. The `provider.rate_limit.headroom` gauge reports available capacity as a percentage. Low headroom indicates approaching limits requiring traffic management or provider quota increase.

Backoff behavior metrics track retry delays and queue depth during rate limiting. The `provider.rate_limit.backoff.duration` histogram captures retry delay distribution. High backoff durations indicate sustained rate limiting requiring investigation.

---

## Provider-Specific Dashboards

Each provider receives a dedicated dashboard showing availability, latency, error rates, and circuit breaker state. Dashboards include time-series charts with correlation between metrics (e.g., latency spike with error rate increase). Comparison charts enable performance benchmarking across providers.

Provider comparison dashboards aggregate metrics across all providers. Summary views show provider health distribution (healthy, degraded, failing) and trend indicators. This enables provider selection for new integrations and identification of underperforming providers.

---

## Incident Response

Provider incidents require specific response procedures. Initial assessment checks provider status pages and community reports. Impact analysis identifies affected operations and tenants using provider-specific dashboards.

Mitigation steps depend on provider status. For provider outage, fallback providers are activated where available. For degraded performance, circuit breakers are monitored and traffic may be rerouted. For rate limiting, traffic is throttled to stay within limits.

Communication templates provide pre-drafted status updates for provider incidents. Post-incident reviews include provider-specific analysis and potentially identify provider replacement or contract renegotiation needs.

---

## Related Documents

- `06-integration/provider-integration`
- `10-observability/metrics`
- `10-observability/operational-alerts`
# Observability - Metrics

## Metadata
```yaml
title: Observability - Metrics
domain: observability
owner: Platform Engineering
criticality: HIGH
runtime-impact: MEDIUM
security-impact: LOW
queue-impact: LOW
provider-impact: LOW
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - 10-observability/tracing
  - 10-observability/logging
related-docs:
  - 10-observability/dashboards
  - 10-observability/operational-alerts
related-queues: []
related-services:
  - metrics-collector
  - prometheus
  - grafana
```

---

## Overview

Metrics provide quantitative measurements of system behavior, enabling performance monitoring, capacity planning, and anomaly detection. This document defines the metrics taxonomy for the Unified Identity and Credential Platform (UICP), establishing standardized measurement patterns across all services.

---

## Core Metrics Categories

### Request Metrics

Request metrics capture the volume, latency, and outcome of API operations. The primary request metric is `uicp.requests.total`, which counts all incoming API calls categorized by method, path, status code, and tenant. This metric supports alerting on unusual traffic patterns and provides baseline utilization data for capacity planning.

Response time metrics use histogram distributions to capture tail latency. The `uicp.request.duration` histogram includes quantile buckets at p50, p75, p90, p95, and p99, enabling precise identification of performance degradation. Response duration directly impacts client experience and should remain below 500ms at p95 for authentication operations.

### Authentication Metrics

Authentication metrics track credential validation success and failure rates. The `uicp.auth.attempts.total` counter records authentication attempts by result (success, failure, rate-limited), credential type (password, API key, OAuth), and tenant. This metric supports security monitoring and fraud detection use cases.

Token issuance metrics track OAuth2 and API key token creation. The `uicp.tokens.issued.total` counter captures token issuance by type, grant type, and tenant, while `uicp.tokens.expired.total` tracks token expiration events. These metrics enable token lifecycle analysis and help identify potential credential misuse.

### Provider Metrics

Provider metrics measure external service integration performance. The `uicp.provider.requests.total` counter records outbound calls to identity providers and credential validation services, tagged by provider name, endpoint, and result. Provider latency is captured in `uicp.provider.latency` histograms with provider-specific quantile breakdowns.

Error rate metrics track provider failures and fallbacks. The `uicp.provider.errors.total` counter captures provider timeouts, HTTP errors, and validation failures, enabling rapid identification of provider degradation. Circuit breaker state transitions are tracked in `uicp.provider.circuit.state`, supporting correlation of service availability with provider health.

### Queue Metrics

Queue metrics monitor asynchronous message processing. The `uicp.queue.messages.pending` gauge reports current queue depth for each queue type (email, notification, audit), while `uicp.queue.messages.processed.total` counts successfully processed messages. Message processing latency is captured in `uicp.queue.processing.duration` histograms.

Dead letter queue metrics track failed message processing. The `uicp.queue.deadletter.size` gauge reports messages in dead letter queues, while `uicp.queue.retry.attempts.total` counts retry attempts per message. These metrics enable identification of processing failures requiring intervention.

---

## Tenant Metrics

Tenant-level metrics provide per-tenant visibility for multi-tenant deployments. The `uicp.tenant.requests.total` counter tracks API usage per tenant, enabling billing and quota management. Tenant-specific latency metrics in `uicp.tenant.latency` identify performance issues affecting specific tenants.

Resource utilization metrics track tenant-specific consumption. The `uicp.tenant.api_keys.active` gauge reports active API keys per tenant, while `uicp.tenant.sessions.active` tracks concurrent sessions. These metrics support tenant capacity planning and help identify resource-intensive tenants requiring attention.

---

## Alerting Thresholds

Critical alerts trigger on `uicp.request.errors.total` rate exceeding 5% over 5 minutes, `uicp.auth.failures.rate` exceeding 10% over 15 minutes, or `uicp.provider.latency.p99` exceeding 2000ms. Warning alerts trigger on p95 latency exceeding 1000ms, queue depth exceeding 10000 messages, or error rate exceeding 1%.

---

## Related Documents

- `10-observability/tracing`
- `10-observability/dashboards`
- `10-observability/operational-alerts`
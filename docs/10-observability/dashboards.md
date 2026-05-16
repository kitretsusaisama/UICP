# Observability - Dashboards

## Metadata
```yaml
title: Observability - Dashboards
domain: observability
owner: Platform Engineering
criticality: MEDIUM
runtime-impact: LOW
security-impact: LOW
queue-impact: LOW
provider-impact: LOW
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 10-observability/metrics
  - 10-observability/logging
related-docs:
  - 10-observability/tracing
  - 10-observability/operational-alerts
related-queues: []
related-services:
  - grafana
  - kibana
```

---

## Overview

Dashboards provide visual representations of system health, performance, and operational status. This document defines the standard dashboard suite for UICP monitoring, enabling operators to quickly assess system state and identify issues requiring attention.

---

## Executive Dashboard

The executive dashboard provides high-level system health overview for leadership and on-call engineers. It displays key performance indicators including total requests per second, overall error rate, average response time, and active sessions. A traffic light system indicates system status (green, yellow, red) based on SLI performance against SLO targets.

The dashboard includes tenant utilization charts showing active tenants, total API calls, and resource consumption distribution. Provider health summary shows external service availability and average latency. Queue status panel displays message backlog and processing rates for all queues. This dashboard refreshes every 30 seconds and supports a 24-hour time range.

---

## Service Dashboard

The service dashboard provides detailed per-service metrics for engineering teams. Each service receives a dedicated panel showing request volume, error rate, latency distributions (p50, p95, p99), and saturation metrics. Service dependencies are visualized showing upstream and downstream call patterns.

Memory and CPU utilization charts show resource consumption with capacity thresholds. Connection pool utilization shows database and cache connection usage. JVM-specific metrics for Java services include heap usage, garbage collection frequency, and thread count. This dashboard supports drill-down from service to endpoint level.

---

## Authentication Dashboard

The authentication dashboard focuses on credential validation and session management. It displays authentication attempt volume by method (password, API key, OAuth), success rate by method, and failure breakdown by reason. Rate limiting metrics show blocked requests and cooldown status.

Token lifecycle metrics display token issuance rate, expiration rate, and revocation events. Session metrics show active sessions, concurrent session distribution, and session duration percentiles. This dashboard supports security monitoring and helps identify brute force attempts or credential stuffing attacks.

---

## Tenant Dashboard

The tenant dashboard provides per-tenant visibility for multi-tenant deployments. Each tenant can be selected to view their specific metrics including request volume, error rate, latency, and resource utilization. Tenant comparison view enables benchmarking across tenants.

Quota consumption charts show API call usage against configured limits. API key inventory displays active keys, usage patterns, and recently created or rotated keys. Billing metrics display resource consumption for chargeback purposes. Tenant administrators can view their own tenant data, while platform operators can view all tenants.

---

## Incident Response Dashboard

The incident response dashboard activates during active incidents to provide centralized visibility. It displays current incident details, affected services, and timeline of events. Real-time metrics show error rate spike, latency degradation, or queue backlog growth.

Log search panel provides integrated log access filtered to the incident timeframe and affected components. Trace sampling shows distributed trace excerpts for failed requests. Communication panel displays incident channel links and on-call roster. This dashboard supports collaborative incident response with role-based access.

---

## Related Documents

- `10-observability/metrics`
- `10-observability/logging`
- `10-observability/operational-alerts`
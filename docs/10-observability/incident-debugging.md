# Observability - Incident Debugging

## Metadata
```yaml
title: Observability - Incident Debugging
domain: observability
owner: Platform Engineering
criticality: HIGH
runtime-impact: MEDIUM
security-impact: MEDIUM
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - 10-observability/tracing
  - 10-observability/logging
  - 10-observability/metrics
related-docs:
  - 10-observability/operational-alerts
  - 10-observability/dashboards
related-queues: []
related-services:
  - all-services
```

---

## Overview

Incident debugging provides systematic approaches for identifying and resolving production issues. This document outlines debugging workflows, tooling, and best practices for efficient incident resolution.

---

## Incident Detection

Detection triggers identify incidents through multiple channels. Automated alerts from monitoring systems detect anomalies in metrics, logs, and traces. Customer reports flag issues not captured by automated systems. Internal testing discovers issues before external impact.

Initial triage assesses incident scope and severity. Scope determination identifies affected services, tenants, and functionality. Severity classification assigns priority (P1-Critical, P2-High, P3-Medium, P4-Low). Initial triage completes within 5 minutes of detection.

Impact assessment quantifies incident effects. User impact identifies affected user count and experience degradation. Business impact assesses revenue, SLA, and compliance implications. Service impact identifies cascading failures and dependencies.

---

## Diagnostic Workflow

The diagnostic workflow follows a systematic approach. Data collection aggregates relevant metrics, logs, and traces for the incident timeframe. Initial hypotheses form potential root causes based on collected data. Hypothesis testing validates or invalidates potential causes.

Metrics analysis examines time-series data for anomalies. Correlation identifies coincident metric changes suggesting causation. Baseline comparison contrasts current values with historical patterns. Trend analysis identifies gradual degradation not visible in snapshots.

Log analysis searches for error patterns. Search queries filter logs by severity, service, and timeframe. Pattern matching identifies repeated error types. Log correlation links related events across services.

Trace analysis reconstructs request paths. Trace identification locates affected traces by correlation ID. Span analysis examines timing and dependencies. Bottleneck identification finds slow operations in the path.

---

## Common Issue Patterns

Authentication issues manifest as elevated auth failure rates. Root causes include provider outages, credential database issues, and configuration changes. Debugging focuses on auth service logs and provider health.

Latency issues appear as response time degradation. Root causes include resource contention, database query issues, and external service slowdown. Debugging focuses on latency percentiles and dependency metrics.

Error rate spikes indicate failures in the system. Root causes include code bugs, infrastructure issues, and external service problems. Debugging focuses on error classification and stack trace analysis.

Queue backlogs indicate processing delays. Root causes include consumer failures, capacity constraints, and message storms. Debugging focuses on queue depth, processing rate, and error patterns.

---

## Debugging Tools

Distributed tracing provides request-level visibility. Jaeger and similar tools enable trace search and visualization. Trace comparison identifies behavioral changes between time periods.

Log aggregation provides centralized log access. Kibana and similar tools enable log search and visualization. Saved searches accelerate common investigation patterns.

Metrics dashboards provide system-wide visibility. Grafana dashboards show service health and trends. Alert annotations correlate incidents with metric changes.

---

## Incident Resolution

Resolution verification confirms issue correction. Testing validates the fix in staging before production deployment. Gradual rollout confirms fix effectiveness at scale. Monitoring confirms metrics return to normal.

Root cause analysis identifies underlying causes. Timeline reconstruction builds accurate event sequence. Contributing factors identify systemic issues enabling the incident. Remediation actions prevent recurrence.

Post-incident review documents lessons learned. Incident summary describes impact and duration. Response evaluation assesses detection time and resolution efficiency. Improvement items address process and tooling gaps.

---

## Related Documents

- `10-observability/tracing`
- `10-observability/logging`
- `10-observability/operational-alerts`
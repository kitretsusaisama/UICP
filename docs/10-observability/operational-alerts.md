# Observability - Operational Alerts

## Metadata
```yaml
title: Observability - Operational Alerts
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
  - 10-observability/metrics
  - 10-observability/dashboards
related-docs:
  - 10-observability/incident-debugging
  - 10-observability/slo-sla-model
related-queues: []
related-services:
  - alert-manager
  - pagerduty
  - opsgenie
```

---

## Overview

Operational alerts notify on-call engineers of issues requiring attention. This document defines alert taxonomy, thresholds, routing, and escalation procedures.

---

## Alert Taxonomy

Alerts are classified by severity and type. Critical alerts (SEV1) indicate service outages or severe degradation requiring immediate response. Warning alerts (SEV2) indicate issues requiring attention but not immediate impact. Info alerts provide operational context without requiring action.

Alert types distinguish different problem categories. Availability alerts detect service outages or severe error rates. Performance alerts detect latency degradation or resource saturation. Capacity alerts detect resource exhaustion approaching limits. Security alerts detect authentication anomalies or access violations.

---

## Alert Thresholds

Availability thresholds trigger on service health. Service unavailable triggers when error rate exceeds 10% over 5 minutes. Partial degradation triggers when error rate exceeds 5% over 5 minutes. These thresholds balance sensitivity with noise reduction.

Performance thresholds trigger on response time. p95 latency exceeded triggers when 95th percentile latency exceeds 1000ms. p99 latency exceeded triggers when 99th percentile latency exceeds 2000ms. Baseline comparison triggers when latency exceeds 2x the 7-day average.

Capacity thresholds trigger on resource utilization. CPU saturation triggers when utilization exceeds 80% sustained for 5 minutes. Memory saturation triggers when utilization exceeds 85%. Queue backlog triggers when depth exceeds 10000 messages.

Security thresholds trigger on threat indicators. Auth failure rate triggers when failed attempts exceed 100 per minute from a single IP. Rate limit exhaustion triggers when requests exceed quota. Suspicious activity triggers on anomalous patterns.

---

## Alert Routing

Routing directs alerts to appropriate responders. Service-based routing sends alerts to the team owning the affected service. Tenant-based routing sends tenant-specific alerts to tenant operations. Severity-based routing escalates critical alerts to on-call engineers.

Notification channels reach responders through multiple paths. PagerDuty and OpsGenie handle critical alert notifications. Slack channels provide team awareness and collaboration. Email provides low-urgency notifications and archives.

On-call rotation defines responder availability. Primary on-call receives all routed alerts. Secondary on-call receives escalation if primary is unavailable. Manager escalation receives alerts not acknowledged within defined timeouts.

---

## Escalation Procedures

Acknowledgment confirms alert receipt. Alerts not acknowledged within 5 minutes escalate to secondary on-call. Alerts not acknowledged within 10 minutes escalate to manager. Acknowledgment stops escalation timer.

Response time expectations define target resolution times. SEV1 alerts require response within 15 minutes. SEV2 alerts require response within 30 minutes. SEV3 alerts require response within 2 hours. Response time tracking measures adherence.

Escalation triggers activate when response expectations are not met. No acknowledgment triggers escalate to next level. No progress triggers escalate when no status update is provided. Impact escalation elevates severity when scope increases.

---

## Alert Tuning

Alert noise reduction minimizes unnecessary notifications. Composite alerts combine related signals to reduce alert volume. Suppression rules disable alerts during maintenance windows.休眠 periods reduce notifications for predictable low-traffic periods.

Alert gap analysis identifies missing coverage. Unalerted incidents identify events not captured by existing alerts. False positive analysis identifies alerts not requiring action. Tuning adjusts thresholds and conditions.

Alert effectiveness measurement tracks outcomes. Mean time to detection measures alert to awareness time. Mean time to resolution measures alert to fix time. Alert volume tracks notification count over time.

---

## Related Documents

- `10-observability/metrics`
- `10-observability/incident-debugging`
- `10-observability/slo-sla-model`
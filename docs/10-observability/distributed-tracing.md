# Observability - Distributed Tracing

## Metadata
```yaml
title: Observability - Distributed Tracing
domain: observability
owner: Platform Engineering
criticality: HIGH
runtime-impact: LOW
security-impact: LOW
queue-impact: LOW
provider-impact: LOW
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - 10-observability/telemetry-pipelines
  - 10-observability/metrics
related-docs:
  - 10-observability/tracing
  - 10-observability/incident-debugging
related-queues: []
related-services:
  - jaeger
  - opentelemetry-collector
```

---

## Overview

Distributed tracing tracks requests across service boundaries, providing end-to-end visibility into complex request flows. This document defines tracing implementation, instrumentation standards, and analysis procedures.

---

## Trace Context

Trace context propagates across service boundaries. Trace ID uniquely identifies the entire request across all services. Span ID identifies the current operation within the trace. Parent span ID links spans in a hierarchy.

Context propagation uses standardized formats. W3C Trace Context is the primary propagation format. B3 propagation supports Zipkin-compatible systems. Custom propagation enables legacy system integration.

Context injection adds trace headers to outgoing requests. HTTP headers carry context in REST calls. Message headers carry context in queue messages. Database context carries context in database operations.

---

## Span Design

Spans represent individual operations within a trace. Span name identifies the operation type (e.g., "auth.validate", "db.query"). Span kind distinguishes client (outgoing) and server (incoming) operations.

Span attributes provide contextual information. HTTP attributes capture method, URL, status code. Database attributes capture query text and duration. Custom attributes capture business-relevant context.

Span events mark notable moments within a span. Error events capture exception details. Message events capture queue publish and consume events. Custom events mark business process milestones.

---

## Instrumentation

Automatic instrumentation captures spans without code changes. HTTP server instrumentation captures incoming requests. HTTP client instrumentation captures outgoing requests. Database instrumentation captures query execution.

Manual instrumentation captures业务-specific operations. Custom spans mark business logic boundaries. Attribute addition enriches spans with business context. Event logging captures notable moments.

Library instrumentation captures framework operations. Queue instrumentation captures publish and subscribe operations. Cache instrumentation captures hit and miss events. External service instrumentation captures provider calls.

---

## Trace Analysis

Trace visualization shows request flow across services. Timeline view shows operation timing and ordering. Dependency graph shows service call relationships. Service map shows architecture topology.

Performance analysis identifies bottlenecks. Duration breakdown shows time spent in each operation. Comparison view contrasts normal and anomalous traces. Top traces lists slowest or errored requests.

Error analysis identifies failure patterns. Error traces filter to failed requests. Exception details show error messages and stack traces. Error frequency tracks error rates per service.

---

## Trace Sampling

Sampling reduces trace volume while preserving diagnostic value. Deterministic sampling samples based on trace ID hash. Consistent sampling makes sampling decisions once per trace. All or nothing sampling samples entire traces or none.

Adaptive sampling adjusts based on load. Rate-based sampling samples at a fixed percentage.尾部 sampling samples traces exceeding latency thresholds. Error sampling samples traces with errors.

Debug sampling captures traces for investigation. Debug headers enable single-trace debugging. Fractional debug sampling captures a percentage of requests. Sampling overrides bypass normal sampling rules.

---

## Trace Storage

Storage retention balances cost and capability. Short-term retention provides detailed data for recent investigation. Long-term retention provides aggregate data for trend analysis. Export capabilities enable external analysis.

Query APIs enable trace access. Trace ID lookup retrieves specific traces. Time-range queries search traces by time. Attribute filters narrow results by span attributes.

Integration connects traces with other observability data. Log correlation links traces to related logs. Metric correlation links traces to metrics. Event correlation links traces to deployment events.

---

## Operational Procedures

Trace pipeline troubleshooting addresses collection issues. Missing traces indicate collection failures. Incomplete traces indicate sampling or timeout issues. Slow traces indicate processing bottlenecks.

Trace analysis procedures guide investigation. Initial trace selection identifies relevant traces. Span navigation explores trace structure. Attribute examination extracts diagnostic details.

Trace optimization improves system efficiency. Span reduction removes unnecessary spans. Attribute reduction removes verbose attributes. Sampling adjustment balances volume and coverage.

---

## Related Documents

- `10-observability/tracing`
- `10-observability/incident-debugging`
- `10-observability/telemetry-pipelines`
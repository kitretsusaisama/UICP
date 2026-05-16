# Observability - Replay Observability

## Metadata
```yaml
title: Observability - Replay Observability
domain: observability
owner: Platform Engineering
criticality: MEDIUM
runtime-impact: MEDIUM
security-impact: LOW
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: LOW
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 10-observability/tracing
  - 10-observability/queue-observability
related-docs:
  - 10-observability/incident-debugging
  - 10-observability/distributed-tracing
related-queues:
  - outbox-queue
  - replay-queue
related-services:
  - replay-service
  - event-store
```

---

## Overview

Replay observability monitors the ability to replay events and requests for debugging, testing, and recovery purposes. This document defines replay metrics, reliability indicators, and operational procedures.

---

## Replay Capability Metrics

Replay availability metrics track the ability to replay historical events. The `replay.available` gauge reports the event retention window in hours. Retention policy determines replay capability duration. Retention below 24 hours triggers alerts.

Replay coverage metrics track the percentage of events eligible for replay. The `replay.coverage.rate` metric reports coverage by event type. Some events may be excluded due to data sensitivity or storage constraints. Coverage below 95% triggers investigation.

Replay capacity metrics track infrastructure readiness. The `replay.capacity.parallel` gauge reports maximum concurrent replay threads. Capacity utilization in `replay.capacity.used` reports current parallel replay count. At-capacity scenarios limit debugging throughput.

---

## Replay Execution Metrics

Replay request metrics track replay operation volume. The `replay.requests.total` counter records replay requests by trigger (manual, automated, debug). Request rate spikes indicate investigation or testing activity.

Replay success metrics track operation outcomes. The `replay.success.rate` reports successful replays as a percentage. Failures are categorized by reason (event not found, processing error, timeout). Success rate below 90% triggers investigation.

Replay latency metrics track operation duration. The `replay.duration` histogram reports replay time from request to completion. Long replay times indicate processing complexity or infrastructure constraints. Duration exceeding 5 minutes triggers alerts.

---

## Event Integrity Metrics

Event completeness metrics verify replay data integrity. The `replay.event.incomplete` count tracks events with missing fields. Incomplete events may indicate storage issues or schema evolution. Non-zero incomplete count triggers data repair.

Event ordering metrics verify timestamp consistency. The `replay.event.out_of_order` count tracks events with timestamp anomalies. Ordering issues may affect replay accuracy. Ordering errors trigger investigation.

Event deduplication metrics track replay idempotency. The `replay.duplicate.detected` count tracks duplicate detection events. Duplicate events indicate upstream issues or replay system problems.

---

## Debugging Replay

Debug replay supports investigation scenarios. Triggers include customer-reported issues, error investigation, and performance analysis. Debug replays are logged for audit and reproducibility.

Selective replay enables targeted event reprocessing. Filters support replay by time range, event type, tenant, or correlation ID. Selective replay reduces resource consumption while enabling targeted investigation.

Replay sandbox provides isolated testing environment. Sandboxed replays execute with mock external dependencies. Sandbox metrics track mock hit rates and fallback frequency.

---

## Recovery Replay

Recovery replay reprocesses failed operations after incident resolution. Recovery triggers include processing failures, data corruption, and service restoration. Recovery replays prioritize by impact and time.

Recovery ordering ensures correct processing sequence. Timestamp-based ordering maintains operation sequence. Out-of-order detection identifies and flags potential issues.

Recovery verification confirms successful completion. Verification checks include expected side effects, output consistency, and state reconciliation. Verification failures trigger manual review.

---

## Operational Procedures

Replay troubleshooting addresses common issues. Event not found indicates retention expiration. Processing errors indicate code bugs or data issues. Timeout indicates infrastructure constraints.

Replay optimization improves performance. Batching combines multiple events per request. Caching reduces redundant fetches. Parallelization increases throughput.

Replay capacity planning ensures adequate resources. Retention planning balances cost and capability. Infrastructure sizing supports peak replay scenarios.

---

## Related Documents

- `10-observability/incident-debugging`
- `10-observability/distributed-tracing`
- `10-observability/queue-observability`
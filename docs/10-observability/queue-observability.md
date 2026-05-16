# Observability - Queue Observability

## Metadata
```yaml
title: Observability - Queue Observability
domain: observability
owner: Platform Engineering
criticality: HIGH
runtime-impact: MEDIUM
security-impact: LOW
queue-impact: HIGH
provider-impact: LOW
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - 10-observability/metrics
  - 10-observability/tracing
related-docs:
  - 05-architecture/async-processing
  - 10-observability/operational-alerts
related-queues:
  - email-queue
  - notification-queue
  - audit-queue
  - outbox-queue
related-services:
  - queue-processor
  - dead-letter-handler
```

---

## Overview

Queue observability monitors asynchronous message processing, ensuring reliable delivery and timely execution. This document defines metrics, alerting, and operational procedures for queue management.

---

## Queue Health Metrics

Queue depth metrics track pending message counts per queue. The `queue.messages.pending` gauge reports current depth for each queue type. Trend analysis shows depth over time, enabling detection of processing backlogs. Depth exceeding 10000 messages triggers warning alerts, exceeding 50000 triggers critical alerts.

Processing rate metrics track message throughput. The `queue.messages.consumed.rate` metric reports messages per second being processed. Processing rate below consumer capacity indicates processing issues. The `queue.messages.produced.rate` metric tracks incoming message rate.

Backlog age metrics show how long pending messages have been waiting. The `queue.backlog.age.p95` histogram reports the 95th percentile message age. High backlog age indicates processing停滞 or capacity constraints. Age exceeding 5 minutes triggers warning alerts, exceeding 15 minutes triggers critical alerts.

---

## Consumer Metrics

Consumer lag metrics track the gap between message production and processing. The `queue.consumer.lag` gauge reports messages waiting per consumer group. High lag indicates consumers falling behind producers. Lag exceeding 1000 messages triggers warning alerts.

Consumer throughput metrics show processing capacity utilization. The `queue.consumer.throughput` histogram reports messages processed per second per consumer. Low throughput compared to expected capacity indicates processing issues or resource constraints.

Error rate metrics track processing failures. The `queue.processing.errors.rate` metric reports failed messages as a percentage of processed messages. Error rate exceeding 5% triggers alerts. Error categorization distinguishes transient errors (retryable) from permanent errors (requires investigation).

---

## Dead Letter Queue Monitoring

Dead letter queue depth is a key reliability indicator. The `queue.deadletter.size` gauge reports messages in dead letter per source queue. Non-zero dead letter indicates processing failures requiring investigation. Dead letter growth rate exceeding 10 per minute triggers alerts.

Dead letter composition analysis identifies failure patterns. The `queue.deadletter.reason` metric tracks failure reasons (timeout, validation error, processing exception). Repeated patterns indicate systemic issues requiring code fixes.

Retry metrics track message retry behavior. The `queue.retry.attempts.distribution` histogram reports retry count distribution. High retry counts indicate persistent failures. Maximum retry exhaustion triggers dead letter placement.

---

## Queue-Specific Monitoring

Email queue monitoring tracks delivery success and retry behavior. Metrics include send attempts, delivery success, bounce rate, and retry count. Provider-specific metrics track email service API errors and rate limits. SPF and DKIM validation failures are monitored separately.

Notification queue monitoring tracks push notification delivery. Metrics include queued notifications, delivery success, device token failures, and click-through rates. Platform-specific metrics track APNS and FCM delivery outcomes.

Audit queue monitoring ensures audit event persistence. Metrics include events queued, events persisted, and write latency. Audit event lag is critical for compliance. Lag exceeding 1 minute triggers critical alerts.

---

## Operational Procedures

Backlog mitigation procedures address processing backlogs. Steps include scaling consumer instances, identifying processing bottlenecks, and addressing resource constraints. For persistent backlogs, message retention policies may need adjustment.

Dead letter investigation procedures process dead letter messages. Investigation includes message content analysis, error stack trace examination, and reproduction attempts. Fixes may require code changes, configuration updates, or data remediation.

Queue capacity planning uses historical data to project future needs. Peak load analysis identifies maximum processing requirements. Growth projections inform infrastructure scaling decisions.

---

## Related Documents

- `05-architecture/async-processing`
- `10-observability/metrics`
- `10-observability/operational-alerts`
# Queue Observability

## Metadata
```yaml
title: Queue Observability
domain: queues
owner: Platform Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-overview.md
  - queue-topology.md
  - retry-engine.md
related-docs:
  - 08-monitoring/alerting-thresholds.md
  - 08-monitoring/dashboards.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
  - webhook-processing
  - audit-logging
  - sms-dlq
  - email-dlq
  - webhook-dlq
  - audit-dlq
related-services:
  - BullMQ
  - Redis cluster
  - Prometheus
  - Grafana
related-providers:
  - All external providers
related-runtime-states:
  - METRICS_COLLECTED
  - ALERT_TRIGGERED
  - ANOMALY_DETECTED
  - DEGRADED
related-threat-models:
  - Metric manipulation
  - Alert fatigue
  - Observability gaps
```

---

## Overview

Queue observability provides visibility into queue health, performance, and failure patterns. UICP implements comprehensive metrics collection, distributed tracing, and alerting to ensure reliable message processing and quick failure detection.

---

## Key Metrics

### Queue Depth Metrics

| Metric | Description | Type |
|--------|-------------|------|
| `uicp.queue.backlog` | Jobs waiting to be processed | Gauge |
| `uicp.queue.active` | Jobs currently being processed | Gauge |
| `uicp.queue.completed` | Jobs completed (rate) | Counter |
| `uicp.queue.failed` | Jobs failed (rate) | Counter |
| `uicp.queue.delayed` | Jobs waiting in retry | Gauge |

### Performance Metrics

| Metric | Description | Type |
|--------|-------------|------|
| `uicp.queue.wait_time` | Time from enqueue to start | Histogram |
| `uicp.queue.processing_time` | Time from start to complete | Histogram |
| `uicp.queue.duration` | Total time in queue | Histogram |
| `uicp.queue.throughput` | Jobs processed per second | Gauge |

### Retry Metrics

| Metric | Description | Type |
|--------|-------------|------|
| `uicp.retry.attempts` | Total retry attempts | Counter |
| `uicp.retry.backoff_duration` | Backoff delay applied | Histogram |
| `uicp.retry.circuit_open` | Circuit breaker state | Gauge |
| `uicp.retry.dead_letter` | Jobs moved to DLQ | Counter |

### Provider Metrics

| Metric | Description | Type |
|--------|-------------|------|
| `uicp.provider.latency` | External API latency | Histogram |
| `uicp.provider.errors` | External API errors | Counter |
| `uicp.provider.rate_limit` | Rate limit hits | Counter |

---

## Distributed Tracing

### Trace Context Propagation

```typescript
// Add trace context to job data
const job = await queue.add('job-name', {
  ...data,
  traceContext: {
    traceId: getCurrentTraceId(),
    spanId: getCurrentSpanId(),
    parentSpanId: getParentSpanId()
  }
});

// Extract in worker
async function processJob(job: Job) {
  const span = tracer.startSpan('job.process', {
    childOf: job.data.traceContext
  });

  try {
    await doWork(job.data);
    span.setTag('outcome', 'success');
  } catch (error) {
    span.setTag('outcome', 'error');
    span.log({ error: error.message });
    throw error;
  } finally {
    span.finish();
  }
}
```

### Span Attributes

| Attribute | Description |
|-----------|-------------|
| `job.id` | Unique job identifier |
| `queue.name` | Queue name |
| `tenant.id` | Tenant identifier |
| `job.attempts` | Current attempt number |
| `job.priority` | Job priority level |

---

## Dashboards

### Overview Dashboard

Shows aggregate queue health:
- Total backlog across all queues
- Processing rate per queue
- Error rate trends
- DLQ depth

### Per-Queue Dashboard

Detailed view for each queue:
- Depth over time (last 24 hours)
- Processing time percentiles (p50, p95, p99)
- Retry rate and backoff distribution
- Worker utilization

### Provider Health Dashboard

External service integration status:
- API latency by provider
- Error breakdown by type
- Rate limit occurrences
- Circuit breaker state

---

## Alerting Rules

### Critical Alerts

| Alert | Condition | Action |
|-------|-----------|--------|
| Queue深度暴增 | backlog > 10000 | Page on-call |
| 死信队列增长 | dlq.growth > 100/hr | Page on-call |
| 延迟激增 | wait_time.p99 > 10s | Page on-call |
| 错误率飙升 | error_rate > 20% | Page on-call |

### Warning Alerts

| Alert | Condition | Action |
|-------|-----------|--------|
| 队列积压 | backlog > 1000 | Create incident |
| 重试频繁 | retry.rate > 50% | Monitor |
| Worker负载高 | utilization > 80% | Scale workers |
| Provider延迟高 | latency.p99 > 5s | Investigate |

### Info Alerts

| Alert | Condition | Action |
|-------|-----------|--------|
| 新DLQ条目 | dlq.new > 0 | Log |
| Circuit打开 | circuit.open = true | Log |

---

## Log Aggregation

### Structured Log Format

```json
{
  "timestamp": "2026-05-16T10:30:00Z",
  "level": "INFO",
  "message": "Job completed",
  "context": {
    "jobId": "job-123",
    "queue": "sms-delivery",
    "tenantId": "tenant-456",
    "attempts": 1,
    "duration": 234,
    "traceId": "trace-789"
  }
}
```

### Key Log Events

- Job enqueued
- Job started processing
- Job completed
- Job failed (with error details)
- Job retried (with attempt number)
- Job moved to DLQ

---

## Retention

| Metric Type | Retention | Resolution |
|-------------|-----------|------------|
| Raw metrics | 7 days | 10 seconds |
| Aggregated | 90 days | 1 minute |
| Traces | 30 days | Full fidelity |
| Logs | 90 days | Full fidelity |

---

## Related Documents

- `09-queues/queue-overview.md`
- `08-monitoring/alerting-thresholds.md`
- `08-monitoring/dashboards.md`
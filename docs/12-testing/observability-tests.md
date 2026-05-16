# Observability Tests

## Metadata
```yaml
title: Observability Tests
domain: monitoring
owner: SRE Team
criticality: MEDIUM
runtime-impact: LOW
security-impact: LOW
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - src/infrastructure/monitoring/prometheus-metrics.service.ts
  - src/infrastructure/monitoring/logger.service.ts
  - src/infrastructure/tracing/jaeger-tracer.service.ts
related-docs:
  - docs/09-operations/monitoring-setup.md
  - docs/09-operations/alerting-rules.md
related-queues:
  - metrics-aggregation
  - trace-export
related-services:
  - MetricsService
  - LoggerService
  - TracingService
```

---

## Overview

Observability tests validate that the system correctly emits metrics, logs, and traces. These tests ensure that operators can monitor system health, debug issues, and analyze performance.

---

## Test Coverage

### Metrics Emission

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Counter increment | Process successful request | Counter increases by 1 |
| Histogram recording | Record request latency | Histogram updated with value |
| Gauge update | Update queue depth | Gauge reflects current value |
| Metric labels | Add tenant_id label | Label attached to metric |

### Log Emission

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Info logging | Process request | Info log with request ID |
| Error logging | Handle exception | Error log with stack trace |
| Structured logging | Log with metadata | JSON with all fields |
| Log level filtering | Set level to WARN | DEBUG logs suppressed |

### Trace Propagation

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Trace creation | Handle incoming request | New trace started |
| Span creation | Process function call | Span created with timing |
| Trace context | Pass trace ID | Context propagates across services |
| Trace sampling | Sample 10% of requests | Sampled traces exported |

### Alert Validation

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| High latency alert | p95 > 500ms | Alert triggered |
| Error rate alert | Error rate > 1% | Alert triggered |
| Queue depth alert | Queue > 10,000 messages | Alert triggered |

---

## Test Implementation

```typescript
describe('Observability', () => {
  describe('Metrics', () => {
    it('should increment counter on request', async () => {
      await request(app).get('/api/v1/providers');

      const metrics = await prometheusClient.getMetrics();
      const counter = metrics.find(m => m.name === 'http_requests_total');

      expect(counter.value).toBe(1);
      expect(counter.labels.method).toBe('GET');
    });

    it('should record latency in histogram', async () => {
      await request(app).get('/api/v1/providers');

      const histogram = await prometheusClient.getHistogram('http_request_duration');
      const buckets = histogram.buckets;

      expect(buckets['0.1']).toBeGreaterThan(0);
    });
  });

  describe('Logging', () => {
    it('should emit structured logs', async () => {
      await providerService.create(validProvider);

      const logs = await logAggregator.getLogs();
      const log = logs.find(l => l.message.includes('provider created'));

      expect(log).toMatchObject({
        tenant_id: 'test-tenant',
        provider_id: expect.any(String),
        timestamp: expect.any(String),
      });
    });
  });

  describe('Tracing', () => {
    it('should propagate trace context', async () => {
      const traceId = 'trace-123';

      await request(app)
        .get('/api/v1/providers')
        .set('X-Trace-ID', traceId);

      const spans = await jaegerClient.getSpans(traceId);
      expect(spans).toHaveLength(3); // API, Service, DB spans
    });
  });
});
```

---

## Validation Checklist

- All metrics have tenant_id label
- Log retention meets 30-day requirement
- Traces stored for 7 days
- Alert rules tested weekly
- Dashboards accurately reflect metrics

---

## Performance Targets

- Metrics emission latency: < 5ms
- Log write latency: < 10ms
- Trace export latency: < 50ms
- Dashboard query time: < 2 seconds
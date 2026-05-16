# Observability Hooks

## Metadata
```yaml
title: Observability Hooks
domain: sdk/observability
owner: platform-team
criticality: MEDIUM
runtime-impact: LOW
security-impact: NONE
queue-impact: NONE
provider-impact: NONE
tenant-impact: LOW
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - hooks.md
related-docs:
  - 10-observability/tracing.md
related-queues: []
related-services:
  - monitoring-service
```

---

## Overview

Observability hooks provide detailed insight into SDK operations, enabling comprehensive monitoring, tracing, and metrics collection. These hooks are specifically designed for production monitoring and debugging.

## Metrics Collection

The SDK automatically tracks key metrics:

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  metrics: {
    enabled: true,
    adapter: new PrometheusAdapter(),
    prefix: 'uicp_client'
  }
});

// Automatic metrics:
// uicp_client_requests_total{method, status}
// uicp_client_request_duration_seconds{method, endpoint}
// uicp_client_errors_total{type, code}
```

## Distributed Tracing

Integrate with distributed tracing systems for request correlation:

```typescript
import { NodeSDK } from '@opentelemetry/sdk-node';

const client = new UICPClient({
  publishableKey: 'uF1...',
  tracing: {
    enabled: true,
    serviceName: 'my-frontend',
    exporter: new OTLPExporter()
  }
});

// All requests automatically include trace context
const user = await client.users.me();
// Trace: span with context propagation
```

## Custom Observability Hooks

Implement custom observability logic:

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  observability: {
    onRequest: (req) => {
      const span = tracer.startSpan('uicp.request', {
        attributes: {
          'http.method': req.method,
          'http.url': req.url
        }
      });
      return span;
    },
    onResponse: (res, span) => {
      span.setAttribute('http.status_code', res.status);
      span.end();
      return res;
    },
    onError: (error, span) => {
      span.recordException(error);
      span.setAttribute('error', true);
      span.end();
      throw error;
    }
  }
});
```

## Performance Monitoring

Track SDK performance metrics:

```typescript
client.on('metrics', (metrics) => {
  console.log('Request latency p50:', metrics.latency.p50);
  console.log('Request latency p99:', metrics.latency.p99);
  console.log('Error rate:', metrics.errorRate);
});

// Custom metrics
client.metrics.increment('custom.metric', { tag: 'value' });
client.metrics.histogram('response.size', sizeInBytes);
```

## Logging Integration

Configure structured logging:

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  logging: {
    level: 'info',
    format: 'json',  // or 'text'
    destinations: ['stdout', 'file'],
    include: ['request', 'response', 'error']
  }
});
```

## Health Checks

Monitor SDK health status:

```typescript
const health = await client.health.check();
console.log(health.status);        // 'healthy' | 'degraded' | 'unhealthy'
console.log(health.components);    // Detailed component status
console.log(health.checks);         // Individual check results
```

## Alerting Configuration

Set up alerting on observability signals:

```typescript
client.on('alert', (alert) => {
  if (alert.type === 'high_error_rate') {
    notify.onCall(alert);
  } else if (alert.type === 'latency_threshold') {
    notify.opsTeam(alert);
  }
});
```

## Integration Examples

### Datadog Integration

```typescript
import { DogStatsD } from 'hot-shots';

const client = new UICPClient({
  metrics: {
    adapter: new DatadogAdapter(new DogStatsD()),
    prefix: 'uicp'
  },
  tracing: {
    enabled: true,
    exporter: new DatadogExporter()
  }
});
```

### New Relic Integration

```typescript
const client = new UICPClient({
  observability: {
    tracing: {
      enabled: true,
      exporter: new NewRelicExporter()
    },
    logging: {
      format: 'json',
      destinations: ['newrelic']
    }
  }
});
```

---

## Related Documents

- `10-observability/tracing.md` - Full tracing documentation
- `hooks.md` - General SDK hooks
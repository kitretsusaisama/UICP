# UICP Runtime Summary

## Metadata

```yaml
title: UICP Runtime Summary
domain: runtime
owner: Runtime Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: HIGH
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - architecture-summary.md
  - queue-first-philosophy.md
related-docs:
  - trust-model-summary.md
  - provider-model-summary.md
related-queues:
  - email-delivery
  - sms-delivery
  - otp-fastlane
  - webhook-processing
  - audit-logging
related-services:
  - api-gateway
  - auth-service
  - token-service
  - communication-service
  - queue-worker
related-providers:
  - twilio
  - sendgrid
  - aws-ses
related-runtime-states:
  - starting
  - running
  - degraded
  - recovering
  - stopping
  - stopped
related-threat-models:
  - mysql-outage
  - redis-degradation
  - queue-storm
  - provider-outage
```

---

## Runtime Model Overview

UICP uses a **queue-first runtime model** where all external operations (email, SMS, webhooks) are processed asynchronously through BullMQ. This prevents cascading failures and ensures exactly-once delivery through idempotency keys.

---

## Request Lifecycle

### 1. Incoming Request
```
Client Request
     │
     ▼
┌─────────────────┐
│ API Gateway     │ ← First hop, auth validation
│ (NestJS)        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ UnifiedAuthGuard│ ← Tenant resolution from credential
│                 │
│ - API Key: uF/sF/pB/tB prefix detection
│ - JWT: tid claim extraction
│ - Session: tenantId from session
└────────┬────────┘
         │
         ▼ (tenant context resolved)
```

### 2. Request Processing
```
Authenticated Request
     │
     ▼
┌─────────────────┐
│ Controller      │ ← HTTP handling, validation
│                 │
│ - DTO validation
│ - Idempotency key extraction/generation
│ - Request enrichment
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Command/Query   │ ← Business logic
│ Handler         │
│                 │
│ - CQRS pattern
│ - Transaction management
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Service Layer   │ ← Domain operations
│                 │
│ - AuthService
│ - TokenService
│ - CommunicationService
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Repository      │ ← Data access
│                 │
│ - TypeORM queries
│ - Redis cache
└────────┬────────┘
         │
         ▼
    Response (sync) OR Queue Job (async)
```

### 3. Async Processing (Queue-First)
```
Queue Job Enqueued
     │
     ▼
┌─────────────────┐
│ BullMQ Worker   │ ← Async processor
│                 │
│ - Job picking
│ - Retry logic
│ - DLQ handling
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Provider Router │ ← Smart selection
│                 │
│ - Region matching
│ - Cost optimization
│ - Health scoring
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ External        │ ← Provider call
│ Provider        │
│                 │
│ - SendGrid, Twilio, etc.
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Event Store     │ ← Lineage recording
│ (MySQL)         │
│                 │
│ - Immutable audit
│ - Lineage tracking
└─────────────────┘
```

---

## Runtime States

### Service States
| State | Description | Transitions |
|-------|-------------|-------------|
| `starting` | Initializing connections, migrations | → running |
| `running` | Normal operation | → degraded, stopping |
| `degraded` | Partial functionality (e.g., cache down) | → running, recovering |
| `recovering` | Restoring from failure | → running, degraded |
| `stopping` | Graceful shutdown | → stopped |
| `stopped` | No traffic accepted | → starting |

### Queue States
| State | Description |
|-------|-------------|
| `pending` | Job waiting in queue |
| `active` | Worker currently processing |
| `completed` | Successfully finished |
| `failed` | Retries exhausted, moved to DLQ |
| `delayed` | Scheduled for future execution |

---

## Connection Management

### Database Connections
| Pool | Default | Max | Purpose |
|------|---------|-----|---------|
| MySQL Write | 10 | 50 | Primary transactions |
| MySQL Read | 20 | 100 | Query operations |
| Connection Timeout | 30s | - | Idle timeout |
| Query Timeout | 30s | - | Query execution |

### Cache Connections
| Pool | Default | Max | Purpose |
|------|---------|-----|---------|
| Redis | 50 | 200 | Sessions, rate limits |
| Pipeline | 100 | - | Bulk operations |

### Queue Connections
| Queue | Priority | Workers | Retry Policy |
|-------|-----------|---------|--------------|
| otp-fastlane | CRITICAL | 10 | 1x immediate |
| email-delivery | MEDIUM | 20 | 3x exponential |
| sms-delivery | HIGH | 15 | 3x exponential |
| webhook-processing | LOW | 5 | 5x linear |
| audit-logging | LOW | 3 | 3x exponential |

---

## Observability

### Metrics Collection
- **Prometheus** metrics via OpenTelemetry
- **Key Metrics**: request_latency, queue_depth, provider_health, tenant_throughput
- **SLO Targets**: p99 < 100ms (auth), p99 < 500ms (async)

### Tracing
- **OpenTelemetry** for distributed tracing
- **Span Attributes**: tenant_id, user_id, operation, provider
- **Export**: Jaeger, Zipkin, or OTLP

### Logging
- **Structured JSON** logs
- **Log Levels**: error, warn, info, debug, trace
- **Correlation**: trace_id, span_id for request chaining

---

## Operational Constraints

| Constraint | Value | Description |
|------------|-------|-------------|
| Max JWT Age | 900s | 15-minute access token |
| Max Refresh Token | 604800s | 7-day refresh window |
| Max Session | 86400s | 24-hour session |
| OTP TTL | 300s | 5-minute OTP validity |
| API Key Grace | 3600s | 1-hour rotation window |
| Rate Limit | 1000/min | Per API key default |
| Queue Job TTL | 24h | Maximum job lifetime |
| DLQ Retention | 7d | Dead letter queue retention |

---

## Runtime Dependencies

### Startup Order
```
1. Config Loading (.env, config service)
2. Database Connection (TypeORM init)
3. Redis Connection (ioris client)
4. Queue Connection (BullMQ manager)
5. Migration Runner (pending migrations)
6. Event Store Init (lineage tables)
7. Health Checks Register (liveness/ready)
8. Route Registration (NestJS bootstrap)
```

### Shutdown Order
```
1. Stop accepting new requests
2. Drain active HTTP connections
3. Drain queue workers (wait for active jobs)
4. Close Redis connections
5. Close MySQL connections
6. Exit process
```

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*
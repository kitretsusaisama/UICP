# UICP Operational Thinking

## Metadata

```yaml
title: UICP Operational Thinking
domain: operations
owner: SRE Team
criticality: HIGH
runtime-impact: HIGH
security-impact: HIGH
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - architecture-summary.md
  - queue-first-philosophy.md
  - provider-model-summary.md
related-docs:
  - engineering-principles.md
  - operational-thinking.md
related-queues:
  - email-delivery
  - sms-delivery
  - otp-fastlane
  - audit-logging
related-services:
  - api-gateway
  - auth-service
  - communication-service
  - tenant-service
  - audit-service
related-providers:
  - twilio
  - sendgrid
  - aws-ses
related-runtime-states:
  - starting
  - running
  - degraded
  - recovering
  - stopped
related-threat-models:
  - mysql-outage
  - redis-degradation
  - provider-outage
  - queue-storm
```

---

## Operational Philosophy

UICP treats operations as a first-class concern. The platform is designed for operability: clear diagnostics, predictable behavior, and self-healing capabilities. Operators should be able to understand system state at a glance and respond to incidents with confidence.

---

## Runbook-Driven Operations

Every service component has a corresponding runbook. Runbooks are indexed by failure mode:

| Failure Mode | Runbook Location |
|--------------|------------------|
| MySQL outage | `/runbooks/database/mysql-outage.md` |
| Redis degradation | `/runbooks/cache/redis-degradation.md` |
| Provider failure | `/runbooks/provider/failover.md` |
| Queue storm | `/runbooks/queue/queue-storm.md` |
| Auth spike | `/runbooks/auth/auth-spike.md` |

---

## Core Operational Patterns

### 1. Health Check Hierarchy

UICP implements a hierarchical health check:

```
┌─────────────────────────────────────────┐
│           Liveness Probe                 │
│   (Process is running?)                 │
└────────────────┬────────────────────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
┌───────────────┐  ┌───────────────┐
│  Readiness    │  │  Dependency   │
│ (Ready to     │  │  Health       │
│  serve?)      │  │ (DB, Redis,   │
└───────┬───────┘  │  Queue OK?)   │
        │         └───────┬───────┘
        ▼                 ▼
┌───────────────┐  ┌───────────────┐
│  Tenant       │  │  Queue        │
│  Resolution   │  │  Depth        │
│  OK           │  │  Normal        │
└───────────────┘  └───────────────┘
```

### 2. Circuit Breaker Patterns

External dependencies are protected by circuit breakers:

| Component | Threshold | Action |
|-----------|-----------|--------|
| Email Provider | 5 failures | Open circuit, fallback to next |
| SMS Provider | 3 failures | Open circuit, use failover |
| MySQL | 10 failures | Open circuit, read-only mode |
| Redis | 5 failures | Open circuit, local fallback |

### 3. Rate Limiting Tiers

Rate limiting is applied at multiple levels:

| Level | Limit | Scope |
|-------|-------|-------|
| Global | 100K/min | All tenants |
| Tenant | 10K/min | Per tenant |
| Key | 1K/min | Per API key |
| Endpoint | Variable | Per endpoint |

---

## Observability Stack

UICP provides complete observability:

### Metrics (Prometheus + Grafana)
- Request latency (p50, p95, p99)
- Error rates by type
- Queue depth and processing time
- Provider health scores
- Tenant usage metrics

### Logs (Structured JSON)
- All logs include: tenantId, keyId, correlationId
- Log levels: ERROR, WARN, INFO, DEBUG
- Sampling: 100% for errors, 10% for debug

### Traces (OpenTelemetry)
- Distributed tracing across all services
- Span attributes for business context
- Automatic trace sampling for high-volume paths

---

## Incident Response Flow

```
┌──────────────────────────────────────────────────────────────┐
│                    Incident Detection                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Auto-Alert  │  │ Manual-Report│  │ Customer-Support   │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
└─────────┼────────────────┼────────────────────┼─────────────┘
          │                │                    │
          ▼                ▼                    ▼
┌──────────────────────────────────────────────────────────────┐
│                    Triage (5 min)                             │
│  - Identify affected component                               │
│  - Determine severity (P1/P2/P3)                             │
│  - Assign incident commander                                 │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│                    Containment (15 min)                       │
│  - Implement immediate mitigation                            │
│  - Enable fallback systems                                   │
│  - Communicate status to stakeholders                        │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│                    Resolution (Variable)                      │
│  - Root cause analysis                                        │
│  - Fix implementation                                         │
│  - Verification                                               │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│                    Post-Incident (24 hrs)                     │
│  - Document timeline                                         │
│  - Update runbooks                                           │
│  - Schedule blameless post-mortem                            │
└──────────────────────────────────────────────────────────────┘
```

---

## SLO Definitions

| Service | Availability | Latency | Errors |
|---------|--------------|----------|--------|
| API Gateway | 99.95% | <100ms p99 | <0.1% |
| Auth Service | 99.95% | <50ms p99 | <0.1% |
| Communication | 99.9% | <500ms p99 | <1% |
| Tenant Service | 99.95% | <20ms p99 | <0.1% |

---

## Capacity Planning

Capacity is managed through:

1. **Auto-Scaling** — Based on queue depth and CPU
2. **Predictive Scaling** — ML-based traffic prediction
3. **Connection Pooling** — Database connection limits
4. **Backpressure** — Reject new work when saturated

### Scaling Triggers

| Metric | Scale-Up | Scale-Down |
|--------|----------|------------|
| Queue Depth | >5,000 | <1,000 |
| CPU Usage | >70% | <30% |
| Memory | >80% | <50% |
| Request Rate | >50K/min | <10K/min |

---

## Emergency Procedures

### API Key Compromise
1. Revoke compromised key via API
2. Rotate affected tenant's keys
3. Audit recent API calls
4. Notify tenant of incident

### Database Outage
1. Failover to read replica (if write failure)
2. Enable read-only mode
3. Monitor DLQ for job recovery
4. Plan for data reconciliation

### Queue Storm
1. Enable backpressure
2. Pause non-critical queues
3. Scale workers horizontally
4. Monitor DLQ for poison messages

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*
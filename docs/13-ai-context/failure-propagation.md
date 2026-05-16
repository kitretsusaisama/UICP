# Failure Propagation - AI Context

## Metadata
```yaml
title: Failure Propagation
domain: ai-context
owner: Platform Team
criticality: CRITICAL
runtime-impact: CRITICAL
security-impact: HIGH
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - incident-model.md
  - retry-model.md
related-docs:
  - 16-failure-models/failure-chains.md
  - 16-failure-models/blast-radius.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
related-services:
  - all-services
related-runtime-states:
  - healthy
  - degraded
  - failed
```

---

## Failure Propagation Paths

### 1. Authentication → Service
```
Redis down → Session lookup fails → 401 to all users
```
**Impact**: Full auth failure, login impossible

### 2. Database → Application
```
MySQL down → Query fails → All mutations fail
```
**Impact**: Complete data unavailability

### 3. Queue → Worker
```
Queue storm → Backlog → Processing delay
```
**Impact**: Delayed notifications

### 4. Provider → Queue
```
Provider down → Retries exhausted → DLQ fill
```
**Impact**: Message loss, delivery failure

---

## Blast Radius Analysis

| Component Failure | Affected Users | Recovery |
|-------------------|----------------|----------|
| Redis (sessions) | All authenticated | In-memory fallback |
| MySQL (primary) | All write operations | Read replicas |
| Single provider | Tenant-specific | Auto-failover |
| Queue (email) | All email users | Retry after fix |
| API Gateway | All requests | Load balancer health |

---

## Failure Isolation Patterns

### Circuit Breaker
- Open: Fail fast, don't overload
- Half-open: Probe health
- Closed: Normal operation

### Bulkhead
- Separate resource pools
- Isolate failures to single tenant
- Prevent cascade

### Timeout
- Request timeout: 30s
- Connection timeout: 10s
- Queue message TTL: 1 hour

---

## Failure Notification

| Failure Type | Alert | Notification |
|--------------|-------|--------------|
| Component down | P0 | On-call + Slack |
| Degraded | P1 | Slack channel |
| Provider issue | P2 | Email |
| Retry exhaustion | P2 | Dashboard |

---

## Recovery Patterns

| Scenario | Recovery | Validation |
|----------|----------|------------|
| Redis restored | In-memory sessions | Login test |
| MySQL restored | Read replicas | Query test |
| Provider back | Resume processing | Send test |
| Queue drained | Process DLQ | Delivery confirmation |

---

## Related Context Files

- `incident-model.md` - Incident handling
- `fallback-model.md` - Failover
- `retry-model.md` - Retry behavior

---

*AI-Ingestible: true | Failure propagation for AI context*
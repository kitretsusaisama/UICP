# Queue Topology

## Metadata
```yaml
title: Queue Topology
domain: queues
owner: Platform Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: CRITICAL
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - queue-overview.md
  - retry-engine.md
  - worker-concurrency.md
related-docs:
  - 03-architecture/infrastructure.md
  - 07-deployment/scaling-strategy.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
  - webhook-processing
  - audit-logging
related-services:
  - BullMQ
  - Redis cluster
  - Worker pods
related-providers:
  - Twilio (SMS)
  - SendGrid (Email)
  - Custom webhook endpoints
related-runtime-states:
  - QUEUED
  - ACTIVE
  - COMPLETED
  - FAILED
  - WAITING
related-threat-models:
  - Queue blocking
  - Priority inversion
  - Resource starvation
```

---

## Overview

UICP's queue topology defines the structure, priorities, and relationships between all message queues. The topology is designed for high throughput, low latency for critical operations, and graceful degradation under load.

---

## Queue Architecture

### Primary Queues

```
┌─────────────────────────────────────────────────────────────┐
│                     UICP Queue Topology                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  otp-fastlane (Priority: CRITICAL)                          │
│  ├── maxConcurrency: 50                                     │
│  ├── ttl: 300s                                             │
│  └── DLQ: None (immediate failure)                          │
│                                                             │
│  sms-delivery (Priority: HIGH)                             │
│  ├── maxConcurrency: 20                                     │
│  ├── ttl: 3600s                                            │
│  └── DLQ: sms-dlq                                          │
│                                                             │
│  email-delivery (Priority: MEDIUM)                         │
│  ├── maxConcurrency: 10                                    │
│  ├── ttl: 7200s                                            │
│  └── DLQ: email-dlq                                        │
│                                                             │
│  webhook-processing (Priority: LOW)                         │
│  ├── maxConcurrency: 5                                     │
│  ├── ttl: 3600s                                            │
│  └── DLQ: webhook-dlq                                      │
│                                                             │
│  audit-logging (Priority: LOW)                             │
│  ├── maxConcurrency: 5                                     │
│  ├── ttl: 1800s                                            │
│  └── DLQ: audit-dlq                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Dead Letter Queues

| DLQ | Source Queue | Retention | Auto-Replay |
|-----|--------------|-----------|-------------|
| sms-dlq | sms-delivery | 30 days | Via API |
| email-dlq | email-delivery | 30 days | Via API |
| webhook-dlq | webhook-processing | 30 days | Via API |
| audit-dlq | audit-logging | 30 days | Manual only |

---

## Priority Levels

### CRITICAL - otp-fastlane

- **Purpose**: OTP generation and delivery
- **Characteristics**: Sub-second latency, no DLQ
- **Failure handling**: Immediate failure to caller
- **SLA**: 99.99% success rate, < 500ms p99

### HIGH - sms-delivery

- **Purpose**: SMS message delivery
- **Characteristics**: High volume, retry with backoff
- **Failure handling**: 5 retries, then DLQ
- **SLA**: 99.9% success rate, < 2s p99

### MEDIUM - email-delivery

- **Purpose**: Email message delivery
- **Characteristics**: Moderate volume, reliable delivery
- **Failure handling**: 5 retries, then DLQ
- **SLA**: 99.5% success rate, < 5s p99

### LOW - webhook-processing, audit-logging

- **Purpose**: Event handling, compliance logging
- **Characteristics**: Best-effort, high tolerance
- **Failure handling**: 3 retries, then DLQ
- **SLA**: 99% success rate, < 30s p99

---

## Queue Relationships

### Job Flow

```
Producer → Queue → Worker → [Success → Complete]
                    → [Retry (up to N) → Retry]
                    → [Exhausted → DLQ]
```

### Priority Inheritance

Child jobs inherit priority from parent:
- OTP verification job spawns SMS delivery job (inherits CRITICAL)
- Webhook event spawns processing job (inherits LOW from source)

### Queue Dependencies

```
otp-fastlane ─────┐
                  │
sms-delivery ────┼──> Independent (no dependencies)
                  │
email-delivery ───┤
                  │
webhook-processing → audit-logging (publishes after completion)
```

---

## Scaling Strategy

### Horizontal Scaling

Workers scale based on queue depth:
- Scale up when `queue depth > worker_count * 10`
- Scale down when `queue depth < worker_count * 2`
- Minimum 2 workers per queue for HA

### Priority Preemption

Under load, lower priority queues yield to higher:
- CRITICAL queue gets 70% of available capacity
- HIGH queue gets 20% of available capacity
- LOW queues share remaining 10%

### Backpressure Mechanisms

- Producer throttling when queue depth exceeds 10,000
- Circuit breaker triggers pause at 50% of max depth
- Graceful degradation drops LOW priority at 80% capacity

---

## Resource Allocation

### Per-Queue Resources

| Queue | CPU | Memory | Network | Connection Pool |
|-------|-----|--------|---------|-----------------|
| otp-fastlane | 2 cores | 2GB | 100 Mbps | 50 |
| sms-delivery | 1 core | 1GB | 50 Mbps | 20 |
| email-delivery | 1 core | 1GB | 50 Mbps | 20 |
| webhook-processing | 0.5 core | 512MB | 20 Mbps | 10 |
| audit-logging | 0.5 core | 512MB | 20 Mbps | 10 |

### Redis Memory Budget

- Total queue data: 10GB max
- Per-queue limit: 2GB
- Job data TTL: Queue TTL + 24 hours
- Metadata overhead: ~500 bytes per job

---

## Monitoring

| Metric | Description |
|--------|-------------|
| `uicp.queue.depth` | Current queue depth per queue |
| `uicp.queue.wait_time` | Time from enqueue to processing start |
| `uicp.queue.processing_time` | Time from processing start to complete |
| `uicp.queue.throughput` | Jobs processed per second |
| `uicp.queue.priority_starvation` | Time lower priority jobs wait |

---

## Related Documents

- `09-queues/queue-overview.md`
- `09-queues/retry-engine.md`
- `09-queues/worker-concurrency.md`
- `09-queues/dead-letter.md`
- `07-deployment/scaling-strategy.md`
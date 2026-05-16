# Distributed Runtime

## Metadata
```yaml
title: Distributed Runtime Architecture
domain: runtime
owner: Runtime Team
criticality: HIGH
runtime-impact: HIGH
security-impact: MEDIUM
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - system-architecture.md
  - queue-first-design.md
related-docs:
  - runtime-summary.md
  - multi-region-strategy.md
  - scaling-strategy.md
related-queues:
  - email-delivery
  - sms-delivery
  - webhook-processing
related-services:
  - api-gateway
  - queue-worker
  - provider-router
related-runtime-states:
  - starting
  - running
  - degraded
  - recovering
```

---

## Overview

UICP runs as a distributed system across multiple nodes, with horizontal scaling at each layer. The runtime distributes load across API servers, queue workers, and provider connections while maintaining consistency through centralized state (MySQL, Redis).

---

## Node Types

### API Nodes

Stateless HTTP servers handling incoming requests. They validate credentials, resolve tenant context, and execute business logic. Multiple instances run behind a load balancer for high availability.

**Characteristics:**
- No local state (all state in MySQL/Redis)
- Auto-scaled based on request volume
- Graceful degradation when dependencies fail

### Queue Workers

Long-running processes consuming jobs from BullMQ. Each worker type handles specific job categories with configurable concurrency.

**Worker Pools:**
- otp-fastlane: 10 workers, priority CRITICAL
- email-delivery: 20 workers, priority MEDIUM
- sms-delivery: 15 workers, priority HIGH
- webhook-processing: 5 workers, priority LOW

### Cache Nodes

Redis cluster provides distributed caching, session storage, and rate limiting. All nodes share the same dataset with automatic sharding.

---

## Service Discovery

Services discover each other through environment configuration. No dynamic service discovery—nodes are configured at deployment time.

```
API_NODES=["10.0.1.10", "10.0.1.11", "10.0.1.12"]
REDIS_HOST=10.0.2.5
MYSQL_HOST=10.0.3.10
```

---

## State Management

### Stateless API Layer

API nodes maintain no local state. All state is external:
- **MySQL**: Persistent data (tenants, users, keys)
- **Redis**: Transient state (sessions, rate limits, locks)

### Distributed Sessions

Sessions stored in Redis with automatic expiration. Session tokens validated against Redis on every request—never locally cached.

```
Session Flow:
1. User authenticates
2. Token stored in Redis with TTL
3. Subsequent requests validate token in Redis
4. Session data includes: tenantId, userId, permissions, metadata
```

---

## Load Distribution

### HTTP Traffic

Round-robin distribution across healthy API nodes. Health checks remove failed nodes from the pool.

### Queue Jobs

BullMQ distributes jobs across worker instances. Each job has priority and retry configuration. Failed jobs move to dead-letter queue after exhaustion.

---

## Consistency Model

### Eventual Consistency

Read operations may lag behind writes by milliseconds. The system favors availability over strong consistency for async operations.

### Strong Consistency

Critical operations (authentication, key validation) use synchronous validation against authoritative stores.

---

## Fault Tolerance

### Retry Logic

- **Idempotent operations**: Infinite retry with exponential backoff
- **Non-idempotent**: Limited retries, then DLQ
- **Circuit breaker**: Opens after 5 failures, resets after 30s

### Graceful Degradation

When dependencies fail, the system degrades gracefully:
- Redis down: Fall back to MySQL for sessions (slower)
- MySQL down: Read-only mode, mutations queued
- Provider down: Queue jobs, retry later

---

## Related Documents

- `02-runtime/request-lifecycle.md`
- `16-failure-models/provider-outages.md`
- `16-failure-models/redis-degradation.md`
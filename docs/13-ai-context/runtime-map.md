# Runtime Map - AI Context

## Metadata
```yaml
title: Runtime Map
domain: ai-context
owner: Platform Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - auth-context.md
related-docs:
  - 14-knowledge-graph/services.graph.json
  - 02-api-gateway/gateway-architecture.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
related-services:
  - api-gateway
  - identity-service
  - notification-service
related-runtime-states:
  - healthy
  - degraded
  - offline
```

---

## Component Overview

| Component | Type | Runtime State | Dependencies |
|-----------|------|---------------|--------------|
| API Gateway | Entry Point | Stateful per request | Redis (validation) |
| Identity Service | Core Logic | Stateless | MySQL, Redis |
| Notification Service | Async Worker | Stateful (queue consumer) | BullMQ, Providers |
| Session Manager | Session State | Stateful | Redis |
| Token Service | Auth Logic | Stateless | Redis, MySQL |

---

## Request Flow Map

```
Client Request
     │
     ▼
[API Gateway] ──(validate credentials)──▶ Redis (session cache)
     │                                          │
     ▼                                          ▼
[Tenant Extraction]                    MySQL (optional)
     │                                          │
     ▼                                          ▼
[Business Logic] ──▶ [Queue Dispatch] ──▶ [Worker Pool]
                                              │
                                              ▼
                                        [Provider Router]
                                              │
                                              ▼
                                        [External Providers]
```

---

## State Transitions

| State | Trigger | Impact |
|-------|---------|--------|
| healthy → degraded | Redis latency > 200ms | Increased retry |
| healthy → degraded | Provider quota hit | Queue backup |
| degraded → offline | MySQL unavailable | Full outage |
| degraded → offline | Redis unavailable | Session loss |

---

## Critical Paths

1. **Authentication Path**: API Key → Gateway → Redis → JWT → Service
2. **Notification Path**: API → Queue → Worker → Provider → External
3. **Token Refresh Path**: Token expiry → Redis validation → New token

---

## Resource Allocation

| Resource | Allocation | Scaling Strategy |
|----------|------------|------------------|
| API Gateway | 1:1000 req/s per instance | Horizontal |
| Worker Pool | 1:500 msgs/s per worker | Vertical |
| Redis | 1GB per 10k sessions | Cluster mode |
| MySQL | 1:50 tenants per primary | Read replicas |

---

*AI-Ingestible: true | Runtime topology for AI context understanding*
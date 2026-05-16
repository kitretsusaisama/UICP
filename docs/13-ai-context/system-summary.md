# UICP System Summary - AI Context

## Metadata
```yaml
title: UICP System Summary (AI-Optimized)
domain: ai-context
criticality: CRITICAL
ai-ingestable: true
version: 1.0.0
```

---

## Executive Summary

UICP is an API-key-centric multi-tenant identity and communication platform. Tenant context is derived from credentials (API Key → JWT → Session), NOT from request headers.

---

## Architecture

- **Pattern**: Hexagonal (Ports & Adapters)
- **Pattern**: CQRS (Command Query Responsibility Segregation)
- **Language**: TypeScript / NestJS
- **Database**: MySQL 8.0+ (event store, lineage)
- **Cache**: Redis 6.0+ (sessions, rate limits)
- **Queue**: BullMQ (async processing)

---

## Auth Model

| Method | Priority | Format |
|--------|----------|--------|
| API Key | 1st | `uF{ULID26}xl` or `sF{ULID26}xl{HMAC44}` |
| JWT | 2nd | RS256 with `tid` claim |
| Session | 3rd | Redis session token |

**Rule**: Tenant ID NEVER from header for authenticated endpoints.

---

## Trust Boundaries

1. **Untrusted**: Client applications, external systems
2. **Trusted**: API Gateway (validates all credentials)
3. **Trusted**: Application services (business logic)
4. **Conditional**: Infrastructure (MySQL, Redis, Queue)

---

## Runtime Invariants

1. Every mutation requires idempotency key
2. Every query must include tenant filter
3. All external I/O goes through queues
4. All providers accessed via abstraction interface
5. Audit logs appended to event store (immutable)

---

## Queue Topology

| Queue | Priority | Failure Impact |
|-------|----------|----------------|
| `otp-fastlane` | CRITICAL | Login failures |
| `sms-delivery` | HIGH | OTP delivery |
| `email-delivery` | MEDIUM | Notifications |
| `webhook-processing` | LOW | Event sync |

---

## Provider Routing

**Selection Order**:
1. Region match (lowest latency)
2. Cost optimization
3. Quota availability
4. Health score
5. Configured default

**Providers**: SES (primary), Resend, Maileroo (email); Msg91 (SMS)

---

## Failure Modes

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| MySQL down | Full outage | Read replicas |
| Redis down | Session loss | In-memory fallback |
| Provider down | Delivery failure | Auto-failover |
| Queue storm | Backlog | DLQ, backpressure |
| Replay attack | Duplicate auth | Idempotency keys |

---

## Security Rules

1. HMAC validation required for secret API keys
2. Rate limits per API key (not per IP)
3. Emergency revocation: instant Redis purge
4. Token refresh: old tokens invalidated
5. Session recreation: previous sessions terminated

---

## Operational Constraints

| Parameter | Value |
|-----------|-------|
| JWT Access Token | 900s (15 min) |
| Refresh Token | 604800s (7 days) |
| Session TTL | 86400s (24 hours) |
| OTP TTL | 300s (5 minutes) |
| API Key Grace Period | 3600s (1 hour) |
| Default Rate Limit | 1000/min |

---

## Scaling Model

- **Horizontal**: Add API Gateway instances (stateless)
- **Vertical**: Scale worker concurrency in BullMQ
- **Database**: Read replicas for queries, sharding for writes
- **Cache**: Redis Cluster for session scaling

---

## Related Context Files

- `14-knowledge-graph/services.graph.json` - Service topology
- `15-runtime-lineage/request-lineage.md` - Request traceability
- `16-failure-models/` - Failure scenarios
- `18-smart-tuning/` - Adaptive optimization

---

*AI-Ingestible: true | This file provides machine-readable context for AI systems*

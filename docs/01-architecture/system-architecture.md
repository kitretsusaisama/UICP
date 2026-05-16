# System Architecture

## Metadata
```yaml
title: System Architecture
domain: architecture
owner: Architecture Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: HIGH
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - hexagonal-architecture.md
  - domain-driven-design.md
  - event-driven-runtime.md
related-docs:
  - architecture-summary.md
  - runtime-summary.md
  - trust-model-summary.md
related-queues:
  - email-delivery
  - sms-delivery
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
related-threat-models:
  - mysql-outage
  - redis-degradation
  - queue-storm
```

---

## Executive Summary

UICP (Unified Integration Communication Platform) is a multi-tenant, event-driven communication platform that abstracts provider complexity while maintaining security, reliability, and observability. The system processes billions of events annually across email, SMS, voice, and webhook channels.

---

## Architectural Layers

### Layer 1: API Gateway (NestJS)

The entry point handles authentication, rate limiting, and request validation. All tenant context is resolved from credentials—not headers—enabling true zero-trust security.

```
Request → UnifiedAuthGuard → API Key/JWT/Session Validation → Tenant Resolution → Controller
```

**Components:**
- UnifiedAuthGuard: Credential-based tenant extraction
- RateLimiter: Per-tenant, per-key rate limits
- RequestValidator: DTO validation, schema enforcement

### Layer 2: Application Core (CQRS)

Business logic follows Command Query Responsibility Separation. Commands handle mutations; queries handle reads. Both flow through domain services that maintain business invariants.

**Components:**
- Command Handlers: Write operations (send-email, create-api-key)
- Query Handlers: Read operations (get-sessions, list-keys)
- Domain Services: Business rules, validation

### Layer 3: Domain Layer

The domain layer contains entities, value objects, and business rules. It is framework-agnostic and testable in isolation.

**Entities:**
- Tenant: Multi-tenant isolation boundary
- User: Identity and authentication
- ApiKey: ULID-based credential with HMAC validation
- Session: Token-based authentication state

### Layer 4: Infrastructure

Infrastructure adapters implement port interfaces defined in the domain layer. This enables swapping implementations (e.g., MySQL to PostgreSQL) without changing business logic.

**Adapters:**
- MySQL Repository: Persistent storage
- Redis Cache: Sessions, rate limits, distributed locks
- BullMQ Queue: Async job processing

---

## Communication Patterns

### Synchronous (HTTP)

Used for operations requiring immediate response:
- Authentication (login, token refresh)
- Key validation
- Health checks

### Asynchronous (Queue-First)

Used for operations requiring guaranteed delivery:
- Email/SMS sending
- Webhook delivery
- Audit logging

---

## Data Flow

```
1. Client sends authenticated request
2. UnifiedAuthGuard extracts tenant from credential
3. Controller validates request DTO
4. Command/Query handler executes business logic
5. Repository persists data (MySQL)
6. Cache invalidates (Redis)
7. If async: Queue job enqueued for provider delivery
8. Worker picks job → Provider Router → External Provider
9. Event Store records lineage
```

---

## Security Architecture

Zero-trust principles applied at every layer:
- No implicit trust between services
- Every credential validated on every request
- Tenant context extracted from credentials, not headers
- HMAC-SHA256 signatures for API key validation

---

## Observability

- **Metrics**: Prometheus via OpenTelemetry, p99 latency SLOs
- **Tracing**: Distributed tracing with trace_id propagation
- **Logging**: Structured JSON with correlation IDs

---

## Related Documents

- `00-platform/architecture-summary.md`
- `00-platform/runtime-summary.md`
- `05-security/zero-trust-model.md`
- `02-runtime/request-lifecycle.md`
# UICP Architecture Summary

## Metadata

```yaml
title: UICP Architecture Summary
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
  - product-overview.md
  - runtime-summary.md
related-docs:
  - trust-model-summary.md
  - queue-first-philosophy.md
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
  - tenant-service
  - communication-service
  - token-service
  - api-key-service
  - audit-service
related-providers:
  - twilio
  - sendgrid
  - aws-ses
  - postmark
related-runtime-states:
  - starting
  - running
  - degraded
  - recovering
  - stopped
related-threat-models:
  - replay-attack
  - jwt-compromise
  - provider-outage
  - mysql-outage
  - redis-degradation
  - queue-storm
```

---

## Architectural Pattern

UICP follows **Hexagonal Architecture** (Ports & Adapters) with **CQRS** (Command Query Responsibility Segregation) for clear separation between write and read operations.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Applications                       │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      API Gateway (NestJS)                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              UnifiedAuthGuard                            │   │
│  │   - API Key validation (tenant resolution)              │   │
│  │   - JWT validation                                      │   │
│  │   - HMAC verification                                   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│    Command Side         │     │    Query Side            │
│  (Write Operations)     │     │  (Read Operations)      │
├─────────────────────────┤     ├─────────────────────────┤
│ - Auth handlers         │     │ - User queries          │
│ - Token operations     │     │ - Session queries       │
│ - API key operations   │     │ - Audit queries         │
└───────────┬─────────────┘     └───────────┬─────────────┘
            │                               │
            ▼                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Application Services                         │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────────────┐ │
│  │ AuthService  │ │ TokenService │ │ ApiKeyService         │ │
│  └──────────────┘ └──────────────┘ └────────────────────────┘ │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────────────┐ │
│  │ TenantService│ │ AuditService │ │ CommunicationService │ │
│  └──────────────┘ └──────────────┘ └────────────────────────┘ │
└─────────────────────────────┬───────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│   Driven Ports          │     │   Driven Ports          │
│  (Infrastructure)       │     │  (Infrastructure)      │
├─────────────────────────┤     ├─────────────────────────┤
│ - IUserRepository       │     │ - ICachePort (Redis)    │
│ - ITenantRepository     │     │ - IQueuePort (BullMQ)  │
│ - ITokenRepository      │     │ - IEmailProvider       │
│ - IApiKeyRepository     │     │ - ISmsProvider         │
└─────────────┬───────────┘     └─────────────┬───────────┘
              │                               │
              ▼                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Infrastructure Adapters                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│  │ MySQL Repository │  │ Redis Cache       │  │ Queue Worker │ │
│  │ - User, Tenant  │  │ - Sessions        │  │ - Email      │ │
│  │ - Token, API Key│  │ - Rate Limits     │  │ - SMS        │ │
│  └──────────────────┘  └──────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### API Gateway Layer
| Component | Responsibility |
|-----------|---------------|
| UnifiedAuthGuard | Primary auth validation, tenant resolution |
| JwtAuthGuard | JWT token validation with tid claim |
| ResponseEnvelopeInterceptor | Standardized response wrapping |
| GlobalExceptionFilter | Consistent error handling |

### Application Layer (Use Cases)
| Service | Domain |
|---------|--------|
| AuthService | Login, signup, OAuth, OTP |
| TokenService | JWT issuance, refresh, validation |
| ApiKeyService | Key creation, rotation, revocation |
| TenantService | Tenant CRUD, migration, quota |
| CommunicationService | Email/SMS dispatch, templates |
| AuditService | Immutable audit logging |

### Infrastructure Layer
| Adapter | Technology |
|---------|------------|
| MySQL Repository | TypeORM, event store |
| Redis Cache | ioredis, sessions + rate limits |
| BullMQ | Queue processing with DLQ |
| Email Providers | SendGrid, AWS SES, Postmark |
| SMS Providers | Twilio, SNS, Vonage |

---

## Data Flow Patterns

### Authentication Flow (API Key)
```
1. Client sends: Authorization: Bearer uF{publishable} or sF{secret}
2. UnifiedAuthGuard extracts key prefix (uF/sF/pB/tB)
3. ApiKeyService validates key via HMAC
4. TenantService resolves tenantId from API key
5. Request proceeds with tenant context (no X-Tenant-ID needed)
```

### Communication Flow (Queue-First)
```
1. Client POSTs /v1/communication/email/send
2. Controller validates request, generates idempotency key
3. CommandHandler enqueues to email-delivery queue
4. Worker picks up job, selects provider via ProviderRouter
5. Provider sends email, updates delivery status
6. Lineage recorded in MySQL event store
```

---

## Technology Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Runtime | Node.js | 18+ |
| Framework | NestJS | 10+ |
| Language | TypeScript | 5+ |
| Database | MySQL | 8.0+ |
| Cache | Redis | 6.0+ |
| Queue | BullMQ | 5+ |
| ORM | TypeORM | 0.3+ |
| Auth | Passport.js | 0.7+ |
| Observability | OpenTelemetry | 1.0+ |

---

## Design Principles

1. **API-Key Centric** — Tenant context from credential, not header
2. **Queue-First** — All external ops async, no cascading failures
3. **Provider Abstraction** — Swap providers without code changes
4. **Zero-Trust** — Every request validated, no implicit trust
5. **AI-Native** — All state machine-readable for RAG retrieval
6. **Replay-Safe** — Idempotency keys prevent duplicate processing

---

## Failure Boundaries

| Component | Failure Mode | Impact | Mitigation |
|-----------|-------------|--------|------------|
| MySQL | Outage | All writes fail | Read replicas, connection pool |
| Redis | Degradation | Session loss | In-memory fallback, circuit breaker |
| Email Provider | Outage | Email delivery fails | Auto-failover chain |
| Queue | Storm | Message backlog | Dead letter queue, backpressure |
| JWT Secret | Compromise | Unauthorized access | Emergency rotation, revocation list |

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*
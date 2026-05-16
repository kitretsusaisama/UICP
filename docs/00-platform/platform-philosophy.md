# UICP Platform Philosophy

## Metadata

```yaml
title: UICP Platform Philosophy
domain: platform
owner: Platform Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: HIGH
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: annual
last-reviewed: 2026-05-16
depends-on:
  - vision.md
  - mission.md
  - architecture-summary.md
related-docs:
  - engineering-principles.md
  - queue-first-philosophy.md
  - provider-model-summary.md
  - operational-thinking.md
related-queues:
  - email-delivery
  - sms-delivery
  - otp-fastlane
  - webhook-processing
related-services:
  - api-gateway
  - auth-service
  - communication-service
  - tenant-service
  - api-key-service
related-providers:
  - twilio
  - sendgrid
  - aws-ses
  - postmark
  - vonage
related-runtime-states:
  - starting
  - running
  - degraded
  - recovering
  - stopped
related-threat-models:
  - provider-outage
  - queue-storm
  - mysql-outage
  - redis-degradation
```

---

## Philosophical Foundation

UICP is built on the belief that identity and communication infrastructure should be **invisible to the business** — requiring zero thought from developers while delivering enterprise-grade security, reliability, and scale.

The platform philosophy rests on three pillars:

1. **Credential-Driven Tenancy** — Trust the credential, not the header
2. **Async-First Operations** — Reliability through queues, not retries
3. **Provider Agnosticism** — Swap implementations without code changes

---

## Credential-Driven Tenancy

Traditional multi-tenant systems rely on HTTP headers (`X-Tenant-ID`) for tenant context. This is fragile because:

- Headers can be spoofed or misconfigured
- Developers forget to pass them consistently
- Proxies may strip or modify headers

UICP derives tenant context from the API key itself. The key structure encodes the tenant identity:

- **Publishable Key** (`uF{ulid}`): Client-facing, limited scope
- **Secret Key** (`sF{ulid}`): Server-side, full access
- **Public Key** (`pB{ulid}`): Read-only operations
- **Test Key** (`tB{ulid}`): Sandbox/development use

This approach ensures:
- Tenant context cannot be bypassed
- Keys are auditable and revocable
- Rotation is seamless without service interruption
- Every operation is traceable to a specific credential

---

## Async-First Operations

Synchronous external calls are the leading cause of cascade failures in distributed systems. UICP adopts a **queue-first** philosophy:

### Why Queue-First?

| Aspect | Synchronous | Queue-First |
|--------|-------------|-------------|
| Failure Mode | Immediate timeout | Retry with backoff |
| Latency | Blocked by provider | Near-instant acknowledgment |
| Scalability | Provider limits apply | Decoupled processing |
| Observability | Lost on timeout | Full job lifecycle |
| Cost | Peak-hour premium | Background processing |

### Implementation Principles

1. **Acknowledge First** — Always return a response before processing
2. **Idempotency Required** — Every job must be safely retryable
3. **DLQ for Failures** — Poison messages go to dead letter, not lost
4. **Backpressure** — Reject new work when queue depth exceeds threshold

---

## Provider Agnosticism

UICP treats external providers as interchangeable resources. The provider abstraction layer enables:

- **Hot Swapping** — Switch providers without deployment
- **Smart Routing** — Choose provider based on latency/cost/availability
- **Cost Optimization** — Route to cheapest provider meeting SLA
- **Compliance** — Switch providers to meet regulatory requirements

The provider model decouples business logic from vendor specifics:

```typescript
interface IEmailProvider {
  send(dto: SendEmailDTO): Promise<SendResult>;
  getStatus(messageId: string): Promise<DeliveryStatus>;
  healthCheck(): Promise<boolean>;
}
```

Each provider implements this interface. The router selects providers based on configurable rules.

---

## Design Philosophy in Practice

### Conservative Defaults
- Rate limits start low, increase based on usage
- Provider timeouts are aggressive (fail fast)
- Encryption is mandatory, not optional
- Audit logging is on by default

### Progressive Disclosure
- Simple auth for 80% of use cases (API key)
- Advanced auth for 20% (JWT, HMAC, OAuth)
- Custom extensions for edge cases

### Operator Experience
- Self-healing infrastructure where possible
- Clear diagnostic paths for failures
- Runbook-first incident response
- Metrics-driven capacity planning

---

## Trade-Offs and Decisions

The platform makes explicit trade-offs:

| Decision | Rationale |
|----------|------------|
| API key over header-based tenancy | Stronger security, fewer misconfigurations |
| BullMQ over in-memory queue | Persistence, cluster support, reliability |
| MySQL over NoSQL | ACID compliance, audit integrity, complex queries |
| TypeORM over raw SQL | Type safety, migration management |
| Redis over local cache | Cluster support, persistence options |

---

## Evolution Philosophy

UICP evolves through:
- **Backward Compatibility** — Never break existing APIs
- **Feature Flags** — Roll out changes gradually
- **Canary Deployments** — Test in production safely
- **Telemetry-Driven** — Data-backed architecture decisions

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*
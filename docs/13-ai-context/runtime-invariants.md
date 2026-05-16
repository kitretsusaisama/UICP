# Runtime Invariants - AI Context

## Metadata
```yaml
title: Runtime Invariants
domain: ai-context
owner: Platform Team
criticality: CRITICAL
runtime-impact: CRITICAL
security-impact: CRITICAL
queue-impact: HIGH
provider-impact: HIGH
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - auth-context.md
  - trust-boundaries.md
related-docs:
  - 02-architecture/invariants.md
  - 10-security/invariant-enforcement.md
related-queues:
  - otp-fastlane
  - sms-delivery
  - email-delivery
related-services:
  - all-services
related-runtime-states:
  - consistent
  - inconsistent
```

---

## Core Invariants

### 1. Tenant Isolation
- All queries MUST include tenant_id filter
- All writes MUST set tenant_id
- Sessions MUST be tenant-scoped (prefixed in Redis)

### 2. Authentication Enforcement
- All mutations require valid credentials
- Tenant ID derived from credential, NOT header
- HMAC validation required for secret API keys

### 3. Idempotency
- All POST/PUT/DELETE require idempotency-key header
- Idempotency keys cached in Redis (24h TTL)
- Duplicate requests return cached response

### 4. Queue Safety
- All external I/O goes through BullMQ
- Messages include tenant context
- Retry policies defined per queue type

### 5. Auditability
- All mutations logged to event store
- Audit logs are append-only (immutable)
- Logs include tenant_id, user_id, timestamp

### 6. Provider Abstraction
- Never call provider APIs directly
- Always use ProviderRouter interface
- Handle failures via configured fallback

---

## Invariant Enforcement

| Invariant | Enforced By | Failure Mode |
|-----------|-------------|---------------|
| Tenant isolation | Repository layer | Data leak |
| Auth enforcement | API Gateway | Unauthorized access |
| Idempotency | Application layer | Duplicate processing |
| Queue safety | Worker middleware | Message loss |
| Auditability | Domain events | Compliance violation |
| Provider abstraction | Service layer | Lock-in |

---

## Verification Rules

1. **Pre-write**: Verify tenant_id present in context
2. **Pre-auth**: Verify credential valid and not expired
3. **Pre-queue**: Verify idempotency key checked
4. **Pre-call**: Verify provider accessed via router
5. **Post-write**: Verify audit event emitted

---

## Related Context Files

- `system-summary.md` - Runtime summary
- `trust-boundaries.md` - Trust rules
- `ai-rules.md` - Implementation constraints

---

*AI-Ingestible: true | Runtime invariants for AI reasoning*
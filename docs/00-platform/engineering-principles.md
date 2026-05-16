# UICP Engineering Principles

## Metadata

```yaml
title: UICP Engineering Principles
domain: engineering
owner: Engineering Team
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
  - architecture-summary.md
  - platform-philosophy.md
related-docs:
  - queue-first-philosophy.md
  - operational-thinking.md
  - quick-start.md
related-queues:
  - audit-logging
  - webhook-processing
related-services:
  - api-gateway
  - auth-service
  - tenant-service
  - audit-service
related-providers: []
related-runtime-states:
  - running
  - degraded
  - recovering
related-threat-models:
  - replay-attack
  - jwt-compromise
  - sql-injection
  - queue-storm
```

---

## Core Principles

### 1. Explicit Over Implicit

Every operation must declare its intent. Implicit assumptions about state, identity, or environment are the root cause of production incidents. UICP enforces explicit context passing:

```typescript
// Explicit tenant resolution from API key
async function resolveTenant(key: string): Promise<TenantContext> {
  const prefix = key.substring(0, 2);
  const keyBody = key.substring(2);

  const apiKey = await this.apiKeyService.validate(prefix, keyBody);
  if (!apiKey || apiKey.revokedAt) {
    throw new UnauthorizedException('Invalid or revoked API key');
  }

  return {
    tenantId: apiKey.tenantId,
    permissions: apiKey.permissions,
    keyId: apiKey.keyId,
  };
}
```

### 2. Fail Fast, Recover Gracefully

Detect failures at the boundary, not in the middle. Use circuit breakers for external dependencies, implement retry with exponential backoff, and always have a fallback path.

| Pattern | Application |
|---------|-------------|
| Circuit Breaker | Provider calls (SendGrid, Twilio) |
| Retry with Backoff | Queue jobs, database operations |
| Bulkhead | Connection pool isolation per tenant |
| Timeout Propagation | Distributed tracing end-to-end |

### 3. Idempotency Everywhere

Every mutation must be idempotent. Use ULID-based idempotency keys to prevent duplicate processing:

```typescript
async function sendEmail(dto: SendEmailCommand): Promise<void> {
  // Check for existing operation with same idempotency key
  const existing = await this.eventStore.findByIdempotencyKey(dto.idempotencyKey);
  if (existing) {
    this.logger.log(`Duplicate operation detected: ${dto.idempotencyKey}`);
    return;
  }

  // Proceed with operation
  await this.emailProvider.send(dto);
  await this.eventStore.record(dto.idempotencyKey, dto);
}
```

### 4. Tenant Isolation by Default

No tenant can impact another tenant's security, performance, or availability. This is enforced through:

- API key as the trust anchor (not HTTP headers)
- Connection pool per tenant (where applicable)
- Rate limiting per tenant, not global
- Audit logs tied to tenant + key pair

### 5. Observability as a First-Class Concern

Every component must emit structured logs, metrics, and traces. Use OpenTelemetry for:

- Distributed tracing across service boundaries
- Custom metrics for business KPIs
- Log aggregation with tenant context

```typescript
@Injectable()
export class AuthService {
  async login(dto: LoginDTO): Promise<AuthResult> {
    const span = this.tracer.startSpan('auth.login');
    span.setAttribute('tenant.id', dto.tenantId);

    try {
      const result = await this.authenticate(dto);
      span.setAttribute('auth.success', true);
      return result;
    } catch (error) {
      span.setAttribute('auth.success', false);
      span.setAttribute('error.type', error.constructor.name);
      throw error;
    } finally {
      span.end();
    }
  }
}
```

### 6. Security by Design

- **Zero Trust**: Every request validated, no implicit trust
- **Defense in Depth**: Multiple security layers (auth, tenant, resource)
- **Cryptographic Agility**: Algorithm rotation without code changes
- **Audit Everything**: Immutable audit trail for compliance

---

## Code Quality Standards

### TypeScript Standards
- Strict null checks enabled
- No implicit `any` types
- Use discriminated unions for state machines
- Leverage readonly for immutability

### Testing Requirements
- Unit tests for all business logic (90%+ coverage target)
- Integration tests for infrastructure adapters
- E2E tests for critical user journeys
- Chaos engineering for resilience validation

### Review Checklist
- [ ] Authentication/authorization verified
- [ ] Tenant isolation enforced
- [ ] Idempotency handled
- [ ] Observability added
- [ ] Error handling complete
- [ ] Circuit breakers in place
- [ ] Dependencies documented

---

## Decision Framework

When faced with architectural decisions, apply this hierarchy:

1. **Security** — Does this compromise tenant isolation or data protection?
2. **Reliability** — Does this introduce single points of failure?
3. **Performance** — Does this meet SLA targets for p99 latency?
4. **Maintainability** — Can operators debug this in production?
5. **Cost** — Is resource usage justified by business value?

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*
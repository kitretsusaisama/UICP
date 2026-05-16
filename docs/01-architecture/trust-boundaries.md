# Trust Boundaries

## Metadata
```yaml
title: Trust Boundaries
domain: security
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - api-key-runtime.md
  - runtime-context.md
  - replay-safe-design.md
related-docs:
  - zero-trust-model.md
  - system-architecture.md
related-queues:
  - all-queues
related-services:
  - all-services
related-runtime-states:
  - running
  - degraded
related-threat-models:
  - all-threat-models
```

---

## Overview

Trust boundaries define where trust ends and untrusted territory begins. Every component outside a boundary is treated as potentially malicious. UICP implements defense-in-depth with multiple trust layers.

---

## Trust Layers

### Layer 1: Internet (Untrusted)

```
┌─────────────────────────────────────────────────────┐
│                     INTERNET                         │
│     (Any client, any IP, any location)             │
└─────────────────────┬───────────────────────────────┘
                      │
                      │ Untrusted
                      ▼
┌─────────────────────────────────────────────────────┐
│                  API GATEWAY                         │
│     (Authentication, rate limiting, validation)    │
└─────────────────────────────────────────────────────┘
```

**Trust Level:** Untrusted

All incoming requests from the internet are untrusted until they pass authentication. No assumptions made about client identity or intent.

**Boundary Controls:**
- TLS required (1.3 minimum)
- Auth required (API key, JWT, or session)
- Rate limiting enforced
- Input validation on all fields

### Layer 2: API Gateway (Trusted)

```
┌─────────────────────────────────────────────────────┐
│                   API GATEWAY                        │
│  UnifiedAuthGuard → Tenant Resolution → Validation │
└─────────────────────┬───────────────────────────────┘
                      │
                      │ Trusted
                      ▼
┌─────────────────────────────────────────────────────┐
│               APPLICATION SERVICES                   │
│         (Business logic, domain services)            │
└─────────────────────────────────────────────────────┘
```

**Trust Level:** Trusted

The API gateway validates credentials and establishes tenant context. Once a request passes authentication, it receives a TenantContext with verified identity.

**Boundary Controls:**
- Credential validation (signature, HMAC, token lookup)
- Tenant context extracted from credential (not header)
- Permission checks before operations
- Request context attached for downstream use

### Layer 3: Domain Services (Trusted)

```
┌─────────────────────────────────────────────────────┐
│               APPLICATION SERVICES                  │
│     (Commands, queries, domain services)            │
└─────────────────────┬───────────────────────────────┘
                      │
                      │ Trusted
                      ▼
┌─────────────────────────────────────────────────────┐
│                  REPOSITORY LAYER                    │
│        (TypeORM, Redis, external calls)            │
└─────────────────────────────────────────────────────┘
```

**Trust Level:** Trusted

Domain services operate with verified tenant context. All operations include tenant ID filtering for data isolation.

**Boundary Controls:**
- Tenant ID always included in queries
- Business rules enforced in domain layer
- No direct user input to database queries
- Authorization checks on every operation

### Layer 4: Repository (Trusted)

```
┌─────────────────────────────────────────────────────┐
│                  REPOSITORY LAYER                    │
│         (TypeORM queries, Redis cache)              │
└─────────────────────┬───────────────────────────────┘
                      │
                      │ Conditional
                      ▼
┌─────────────────────────────────────────────────────┐
│                  DATA STORES                         │
│              (MySQL, Redis)                         │
└─────────────────────────────────────────────────────┘
```

**Trust Level:** Conditional

Repository layer talks to MySQL and Redis. These are behind firewall but still considered part of the trust boundary.

**Boundary Controls:**
- Connection pooling limits
- Query timeout enforcement
- SQL injection prevention (parameterized queries)
- Redis key namespace isolation

### Layer 5: External Providers (Untrusted)

```
┌─────────────────────────────────────────────────────┐
│                   WORKER                             │
│         (Queue processing, provider calls)          │
└─────────────────────┬───────────────────────────────┘
                      │
                      │ Untrusted
                      ▼
┌─────────────────────────────────────────────────────┐
│              EXTERNAL PROVIDERS                      │
│      (SendGrid, Twilio, AWS, Webhooks)             │
└─────────────────────────────────────────────────────┘
```

**Trust Level:** Untrusted

External providers are outside the trust boundary. Responses not trusted, timeouts handled, failures retried.

**Boundary Controls:**
- Timeout on all provider calls
- Response validation and sanitization
- Circuit breaker for failing providers
- Data minimization (PII removed before sending)

---

## Trust Mapping

### Component Trust Levels

| Component | Trust Level | Justification |
|-----------|-------------|---------------|
| Internet | Untrusted | Any client, any IP |
| API Gateway | Trusted | Validates all credentials |
| UnifiedAuthGuard | Trusted | Extracts tenant from credentials |
| Controller | Trusted | Has validated context |
| Command Handler | Trusted | Business logic with context |
| Domain Service | Trusted | Enforces business rules |
| Repository | Trusted | Filters by tenant |
| MySQL | Conditional | Behind firewall |
| Redis | Conditional | Behind firewall |
| External Provider | Untrusted | Outside control |

### Credential Trust

| Credential Type | Trust Level | Validation |
|-----------------|-------------|------------|
| API Key (secret) | High | HMAC-SHA256 verification |
| API Key (publishable) | Medium | Key lookup only |
| JWT | High | Signature + claim validation |
| Session Token | High | Redis validation |
| Internal Service | High | mTLS + shared secret |

---

## Boundary Enforcement

### Data Flow Validation

```typescript
async function enforceBoundary(operation: Operation, context: TenantContext): Promise<void> {
  // 1. Verify context exists
  if (!context.tenantId) {
    throw new ForbiddenException('No tenant context');
  }

  // 2. Verify permissions for operation
  if (!hasPermission(context.permissions, operation.requiredPermission)) {
    throw new ForbiddenException('Insufficient permissions');
  }

  // 3. Verify tenant isolation in data
  if (operation.data.tenantId && operation.data.tenantId !== context.tenantId) {
    throw new ForbiddenException('Tenant mismatch');
  }

  // 4. Log boundary crossing
  await this.auditLog.log({
    action: 'boundary.cross',
    from: operation.source,
    to: operation.target,
    tenantId: context.tenantId,
    operation: operation.type,
  });
}
```

### Cross-Boundary Calls

```typescript
async function callExternalProvider(provider: Provider, data: ProviderRequest): Promise<ProviderResponse> {
  // 1. Validate input (sanitization)
  const sanitized = this.sanitizer.sanitize(data);

  // 2. Set timeout
  const timeout = 5000;
  const result = await Promise.race([
    provider.send(sanitized),
    this.timeout(timeout),
  ]).catch(e => ({ error: e.message }));

  // 3. Validate response
  if (result.error) {
    throw new ProviderException(result.error);
  }

  // 4. Log cross-boundary call
  await this.auditLog.log({
    action: 'provider.call',
    provider: provider.name,
    tenantId: data.tenantId,
    success: !result.error,
  });

  return result;
}
```

---

## Related Documents

- `api-key-runtime.md`
- `runtime-context.md`
- `replay-safe-design.md`
- `05-security/zero-trust-model.md`
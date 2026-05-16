# Tenant Isolation

## Metadata
```yaml
title: Tenant Isolation
domain: security
owner: Platform Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: HIGH
provider-impact: MEDIUM
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/zero-trust-model.md
  - 05-security/threat-model.md
related-docs:
  - 05-security/encryption-model.md
  - 08-data/schema-overview.md
  - 17-adrs/ADR-002-domain-resolution.md
related-queues:
  - provider:*
  - tenant:*
related-services:
  - TenantResolver
  - Repository Layer
  - RowLevelSecurity
related-runtime-states:
  - tenant-resolved
  - cross-tenant-attempt
  - isolated
```

---

## Executive Summary

Tenant isolation ensures that each tenant's data and resources are completely separated from other tenants. This is a core security requirement for multi-tenant systems. UICP enforces tenant isolation at every layer of the stack.

---

## Isolation Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      REQUEST LAYER                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Tenant A   │  │  Tenant B   │  │  Tenant C   │             │
│  │  Requests   │  │  Requests   │  │  Requests   │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
└─────────┼────────────────┼────────────────┼────────────────────┘
          │                │                │
          ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   TENANT RESOLVER                               │
│  Extract tenantId from credential (NOT from request!)          │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                 CONTEXT PROPAGATION                             │
│  TenantContext: { tenantId, userId, permissions }              │
│  Carried through: ThreadLocal / Context Propagation           │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
┌─────────────────┐ ┌───────────┐ ┌─────────────────┐
│   Queues        │ │  Cache    │ │   Database      │
│  (per-tenant)  │ │ (partitioned)│ │ (row-filtered) │
└─────────────────┘ └───────────┘ └─────────────────┘
```

---

## Isolation Mechanisms

### 1. Tenant ID Extraction (Critical)

The tenant ID MUST be extracted from the validated credential, never from request parameters or headers.

```
UNSAFE (Do NOT use):
GET /api/resources?tenant_id=tenant_abc
X-Tenant-ID: tenant_abc

SAFE (CORRECT):
GET /api/resources
Authorization: Bearer {jwt_with_tenant_claim}
# Tenant extracted from JWT 'tenant_id' claim
```

**Failure Mode**: Attacker manipulates request to access other tenant's data.

**Recovery Strategy**:
1. Audit all endpoints for tenant_id in parameters
2. Implement automated scanning for isolation violations
3. Add integration tests for cross-tenant access attempts

### 2. Database Row-Level Isolation

All database queries MUST include tenant_id filter.

```typescript
// UNSAFE - Do NOT use
const users = await userRepo.findAll();

// SAFE - Always include tenant filter
const users = await userRepo.findByTenantId(context.tenantId);
```

**Query Interceptor**:
```typescript
@Injectable()
export class TenantQueryInterceptor {
  intercept(query: any, context: TenantContext) {
    // Automatically inject tenant_id where missing
    if (!query.where.tenantId) {
      query.where.tenantId = context.tenantId;
    }
    return query;
  }
}
```

**Failure Mode**: Developer forgets to add tenant filter, exposes cross-tenant data.

**Recovery Strategy**:
1. Enforce tenant_id in repository base class
2. Automated query analysis in CI/CD
3. Periodic database access audits

### 3. Queue Isolation

Queues are namespaced by tenant to prevent message leakage.

```
Queue Naming:
provider:email:send        → tenant-specific: provider:tenant_abc:email:send
provider:sms:send         → tenant-specific: provider:tenant_abc:sms:send
```

**Implementation**:
- RabbitMQ virtual hosts per tenant (enterprise)
- Namespace prefix for shared infrastructure
- Message metadata includes tenant_id for auditing

**Failure Mode**: Message routed to wrong tenant queue.

**Recovery Strategy**:
1. Queue consumer validates tenant_id in message
2. Dead letter queue for misrouted messages
3. Message tracing through lineage system

### 4. Cache Isolation

Redis keys are namespaced to prevent data leakage.

```
Key Format: {tenantId}:{resource}:{id}

Examples:
tenant_abc:api-key:01ARZ3NDEKTSV4RRFFQ69G5FAV
tenant_abc:session:abc123def456
tenant_abc:rate-limit:api-key:01ARZ3NDEKTSV4RRFFQ69G5FAV
```

**Failure Mode**: Cache key collision exposes tenant data.

**Recovery Strategy**:
1. Enforce tenant prefix in Redis client
2. Regular key pattern audits
3. Redis ACLs for tenant-specific users

---

## Trust Boundaries

| Layer | Isolation Method | Trust Level |
|-------|-----------------|-------------|
| API Gateway | Token validation | BOUNDARY |
| Application | Tenant context | TRUSTED |
| Repository | Row filtering | TRUSTED |
| Database | Tenant column | ISOLATED |
| Cache | Key namespacing | ISOLATED |
| Queue | Topic partition | ISOLATED |

---

## Cross-Tenant Protection

### Attempt Detection

```
All access attempts logged with:
- tenantId (from credential)
- requestedTenantId (from resource)
- action performed
- result (allow/deny)
```

**Alerting**: If requestedTenantId != tenantId, immediately flag as security event.

### Response Validation

All responses validated before delivery:

```typescript
function validateResponse(data: any, context: TenantContext): void {
  if (data.tenantId && data.tenantId !== context.tenantId) {
    throw new SecurityViolationError('Cross-tenant data leakage detected');
  }
}
```

---

## Failure Modes and Recovery

| Failure Mode | Impact | Recovery |
|--------------|--------|----------|
| Tenant context missing | CRITICAL | Reject request, log error |
| Cross-tenant query | CRITICAL | Audit affected data, patch code |
| Queue misrouting | HIGH | Requeue with correct tenant |
| Cache key collision | HIGH | Purge affected keys, restart |
| Audit log gap | MEDIUM | Implement log verification |

---

## Related Documents

- `05-security/zero-trust-model.md`
- `05-security/threat-model.md`
- `05-security/encryption-model.md`
- `08-data/schema-overview.md`
# Trust Boundaries - AI Context

## Metadata
```yaml
title: Trust Boundaries
domain: ai-context
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
  - system-summary.md
  - security-rules.md
related-docs:
  - 10-security/threat-model.md
  - 11-compliance/audit-requirements.md
related-queues:
  - webhook-processing
related-services:
  - api-gateway
  - identity-service
  - audit-service
related-runtime-states:
  - trusted
  - untrusted
  - conditional
```

---

## Trust Zones

### Zone 1: Untrusted
- Client applications
- External webhooks
- Third-party callbacks
- Public API consumers

**Constraints**: All input must be validated, no sensitive data exposed

### Zone 2: Boundary (API Gateway)
- Load balancer
- API Gateway
- Rate limiter
- Auth validator

**Constraints**: Must validate all credentials, enforce tenant isolation

### Zone 3: Trusted
- Application services
- Business logic handlers
- Repository layer
- Internal utilities

**Constraints**: Runs with tenant context, accesses tenant data

### Zone 4: Conditional
- Redis (cache)
- MySQL (storage)
- BullMQ (queue)
- Provider APIs

**Constraints**: Behind firewall, require auth, encrypted transit

---

## Trust Boundary Rules

| Boundary | Rule | Enforcement |
|----------|------|-------------|
| Zone 1 → Zone 2 | Credential validation | API Gateway middleware |
| Zone 2 → Zone 3 | Tenant context injection | Auth interceptor |
| Zone 3 → Zone 4 | Connection encryption | TLS 1.3, mTLS for MySQL |
| Zone 1 → Zone 4 | NEVER direct | Blocked at Gateway |

---

## Data Flow Classification

| Data Type | Trust Level | Handling |
|-----------|-------------|----------|
| API Keys | Untrusted until validated | HMAC check, then trusted |
| JWT Tokens | Trusted if valid | Signature + expiry check |
| Session Tokens | Trusted if valid | Redis lookup |
| Tenant Data | Always trusted | Scoped to tenant_id |
| Provider Credentials | Always trusted | Encrypted at rest |
| Audit Logs | Always trusted | Append-only, immutable |

---

## Cross-Boundary Protections

1. **Input Validation**: All Zone 1 input sanitized
2. **Output Encoding**: All Zone 4 output encoded
3. **Tenant Isolation**: Queries always filtered by tenant_id
4. **Credential Rotation**: API keys rotated every 90 days

---

## Related Context Files

- `10-security/threat-model.md` - Threat analysis
- `ai-rules.md` - AI implementation constraints
- `system-summary.md` - Architecture overview

---

*AI-Ingestible: true | Trust boundary definitions for AI context*
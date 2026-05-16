# Security Rules - AI Context

## Metadata
```yaml
title: Security Rules
domain: ai-context
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - system-summary.md
  - trust-boundaries.md
  - replay-model.md
related-docs:
  - 10-security/threat-model.md
  - 10-security/mitigation-strategies.md
  - 11-compliance/audit-requirements.md
related-queues: []
related-services:
  - api-gateway
  - identity-service
  - token-service
related-runtime-states:
  - secure
  - compromised
  - recovering
```

---

## Authentication Rules

1. **API Key Validation**
   - Public keys (`uF`): ULID format check only
   - Secret keys (`sF`/`tB`): HMAC signature required
   - Rate limit: 1000/min per key

2. **JWT Validation**
   - Algorithm: RS256 only
   - Required claims: `tid`, `sub`, `exp`, `iat`
   - Expiry: 900s for access, 604800s for refresh

3. **Session Validation**
   - Redis lookup required
   - TTL: 86400s (24 hours)
   - Sliding expiration on activity

---

## Authorization Rules

1. **Tenant Isolation**
   - All queries filtered by tenant_id
   - All writes include tenant_id
   - Cross-tenant access: NEVER

2. **Permission Model**
   - Role-based access control (RBAC)
   - Resource-level permissions
   - Audit all permission changes

---

## Data Protection Rules

1. **Encryption at Rest**
   - MySQL: AES-256 for sensitive fields
   - Redis: Encryption enabled
   - Backup: Encrypted dumps

2. **Encryption in Transit**
   - All external: TLS 1.3
   - MySQL: mTLS for replication
   - Internal: Service mesh

3. **Sensitive Data**
   - Never log passwords, tokens, keys
   - Mask API keys in all logs
   - Redact PII in telemetry

---

## Emergency Response Rules

| Scenario | Action | SLA |
|----------|--------|-----|
| HMAC secret compromise | Revoke all secret keys | < 15 min |
| JWT private key compromised | Rotate keys, invalidate sessions | < 15 min |
| Redis accessible externally | Firewall immediately | < 5 min |
| Data exfiltration | Isolate, investigate | < 30 min |

---

## Compliance Rules

1. **Audit Logging**: All mutations logged
2. **Data Retention**: 7 years for audit logs
3. **Access Review**: Quarterly permission audit
4. **Penetration Testing**: Annual external test

---

## Related Context Files

- `trust-boundaries.md` - Trust levels
- `replay-model.md` - Replay protection
- `ai-rules.md` - Implementation constraints

---

*AI-Ingestible: true | Security rules for AI context*
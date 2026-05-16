# Threat Model

## Metadata
```yaml
title: Threat Model
domain: security
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/zero-trust-model.md
  - 16-failure-models/replay-attacks.md
related-docs:
  - 05-security/replay-protection.md
  - 05-security/tenant-isolation.md
  - 05-security/api-key-security.md
related-queues: []
related-services:
  - UnifiedAuthGuard
  - ApiKeyService
  - TokenService
related-runtime-states:
  - authenticated
  - unauthenticated
  - compromised
```

---

## Executive Summary

This threat model identifies attack vectors against UICP's authentication, authorization, and tenant isolation systems. The model follows STRIDE methodology and assumes an adversarial environment where any component may be compromised.

---

## Attack Surface Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        INTERNET                                  │
│                   (Untrusted Zone)                              │
└─────────────────────────┬───────────────────────────────────────┘
                          │ HTTP/HTTPS
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    API GATEWAY                                  │
│              (Authentication Boundary)                          │
│  - Rate limiting per API key                                    │
│  - Request signing validation                                   │
│  - Nonce/replay protection                                      │
└─────────────────────────┬───────────────────────────────────────┘
                          │ Authenticated Request
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   APPLICATION LAYER                              │
│           (Tenant Isolation Boundary)                          │
│  - Tenant resolver validates tenant_id from credential          │
│  - Row-level access control                                     │
│  - Audit logging                                                │
└────────────┬─────────────────┬───────────────────────────────────┘
             │                 │
             ▼                 ▼
    ┌──────────────┐   ┌──────────────┐
    │   MySQL      │   │    Redis    │
    │ (Tenant      │   │  (Session   │
    │  Segmented)  │   │   Cache)    │
    └──────────────┘   └──────────────┘
```

---

## Threat Categories

### T1: Credential Theft

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| API Key interception | HIGH | CRITICAL | TLS 1.3 mandatory, key rotation |
| JWT token theft | MEDIUM | HIGH | Short expiry (15 min), HTTP-only cookies |
| Session hijacking | MEDIUM | HIGH | Redis validation, IP binding |
| Database credential leak | LOW | CRITICAL | Encrypted at rest, key rotation |

**Failure Mode**: If credentials are stolen, attacker gains tenant access. Recovery requires emergency revocation.

**Recovery Strategy**:
1. Invalidate all sessions for affected tenant
2. Rotate compromised API keys
3. Force re-authentication for all users
4. Review and patch vulnerability that enabled theft

### T2: Replay Attacks

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Request replay | HIGH | MEDIUM | Nonce validation, timestamp checks |
| Token replay | MEDIUM | HIGH | One-time use validation, expiry |
| Webhook replay | LOW | MEDIUM | Event ID deduplication |

**Failure Mode**: Valid requests captured and resent, causing duplicate operations or unauthorized access.

**Recovery Strategy**:
1. Implement idempotency keys at application layer
2. Deploy nonce cache in Redis with TTL
3. Add request timestamp validation (max 5 min skew)

### T3: Tenant Isolation Bypass

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Tenant ID injection | MEDIUM | CRITICAL | Tenant ID extracted from credential, not request |
| Cross-tenant query | LOW | CRITICAL | Row-level filtering, SQL injection prevention |
| Privilege escalation | LOW | CRITICAL | Role-based access control, principle of least privilege |

**Failure Mode**: Attacker accesses another tenant's data or gains elevated privileges.

**Recovery Strategy**:
1. Audit all data access for isolation violations
2. Implement tenant context in all queries
3. Deploy automated tenant isolation tests

### T4: API Key Compromise

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Key generation algorithm exposure | LOW | CRITICAL | ULID randomness, HMAC secret isolation |
| Key brute force | MEDIUM | CRITICAL | Rate limiting, key entropy (44+ chars) |
| Key leakage in logs | MEDIUM | HIGH | Log masking, secure logging |

**Failure Mode**: Attacker generates valid API keys or uses compromised keys.

**Recovery Strategy**:
1. Emergency revocation endpoint
2. Automatic key rotation schedule
3. Secret rotation procedure

### T5: Man-in-the-Middle

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| TLS interception | LOW | HIGH | Certificate pinning, TLS 1.3 only |
| DNS hijacking | LOW | HIGH | DNSSEC, certificate validation |

---

## Trust Boundaries

| Boundary | Trust Level | Justification |
|----------|-------------|----------------|
| Internet → API Gateway | UNTRUSTED | All input potentially malicious |
| API Gateway → Application | TRUSTED | Credentials validated |
| Application → Repository | TRUSTED | Tenant context established |
| Repository → Database | CONDITIONAL | Within VPC |

---

## Security Invariants

1. **Tenant ID Source of Truth**: Tenant ID MUST be extracted from validated credential, never from request headers or parameters.

2. **Credential Validation Every Request**: No caching of validation results; every request validates its credential.

3. **Fail Secure**: Authentication failures must deny access, not default to allow.

4. **Audit Everything**: All authentication decisions logged with tenant context.

---

## Related Documents

- `05-security/replay-protection.md`
- `05-security/tenant-isolation.md`
- `05-security/api-key-security.md`
- `16-failure-models/replay-attacks.md`
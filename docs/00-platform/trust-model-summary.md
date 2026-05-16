# UICP Trust Model Summary

## Metadata

```yaml
title: UICP Trust Model Summary
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
  - architecture-summary.md
  - runtime-summary.md
related-docs:
  - 05-security/zero-trust-model.md
  - 16-failure-models/replay-attacks.md
  - 16-failure-models/jwt-compromise.md
related-queues:
  - audit-logging
  - otp-fastlane
related-services:
  - api-gateway
  - auth-service
  - token-service
  - api-key-service
related-providers: []
related-runtime-states:
  - running
  - degraded
  - compromised
related-threat-models:
  - replay-attack
  - jwt-compromise
  - api-key-leakage
  - tenant-isolation-breach
```

---

## Zero-Trust Principles

UICP implements **Zero-Trust** security where no component is implicitly trusted. Every request must prove its identity and authorization, regardless of origin (internal/external).

### Core Principles

1. **Never Trust, Always Verify** — Every request validated, no network location assumed
2. **Least Privilege** — Minimal permissions granted, just-in-time access
3. **Assume Breach** — Design for lateral movement prevention
4. **Explicit Verification** — All trust decisions must be authenticated

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│                         UNTRUSTED ZONE                              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐ │
│  │ Client Apps    │  │ Public Network │  │ 3rd Party Webhooks    │ │
│  └───────┬────────┘  └───────┬────────┘  └──────────┬───────────┘ │
└──────────┼───────────────────┼──────────────────────┼──────────────┘
           │                   │                      │
           ▼                   ▼                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         BOUNDARY (Edge)                             │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  UnifiedAuthGuard                                            │  │
│  │  - Bearer token extraction                                   │  │
│  │  - API Key prefix validation (uF/sF/pB/tB)                  │  │
│  │  - HMAC verification for secret keys                        │  │
│  │  - Tenant resolution from credential                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      TRUSTED ZONE (Internal)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  │
│  │ API Gateway │  │ Auth Service│  │Token Service│  │API Key Svc│  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  │
│  │ Tenant Svc  │  │Audit Service│  │Comms Service│  │Queue Worker│  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘  │
└─────────────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      CONDITIONAL ZONE (Infra)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │   MySQL     │  │   Redis     │  │  BullMQ     │                │
│  │ (read replica│ │(cache fallback│ │  (queue)   │                │
│  └─────────────┘  └─────────────┘  └─────────────┘                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Authentication Methods

### Priority Order
1. **API Key** (tenantId from key) — Primary
2. **JWT** (tid claim) — Session-based
3. **Session** (tenantId from session) — Fallback

### API Key Trust Model
| Prefix | Type | Trust Level | HMAC Required |
|--------|------|-------------|---------------|
| `uF` | Live Publishable | Medium | No |
| `sF` | Live Secret | High | Yes |
| `pB` | Dev Publishable | Low | No |
| `tB` | Dev Secret | Medium | Yes |

### JWT Trust Model
- **Algorithm**: RS256 (asymmetric)
- **Required Claims**: `sub`, `tid`, `exp`, `iat`
- **Validation**: JWKS lookup, signature verification, expiration check

---

## Authorization Model

### RBAC + ABAC Hybrid
```
┌────────────────────────────────────────────────────────────┐
│                    Authorization Check                     │
│  ┌──────────────────┐    ┌──────────────────────────────┐ │
│  │ RBAC (Role)      │ +  │ ABAC (Policy)                │ │
│  │ - roleId         │    │ - timeRange                  │ │
│  │ - permissions    │    │ - ipRange                    │ │
│  │ - tenantId       │    │ - devicePosture              │ │
│  └──────────────────┘    └──────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
```

### Policy Example
```json
{
  "effect": "allow",
  "actions": ["read:*", "write:profile"],
  "conditions": {
    "timeRange": { "start": "09:00", "end": "17:00", "timezone": "America/New_York" },
    "ipRange": ["192.168.1.0/24"],
    "devicePosture": ["compliant", "verified"]
  }
}
```

---

## Security Invariants

| Invariant | Description |
|-----------|-------------|
| **Tenant ID from Credential** | `tenantId` NEVER derived from X-Tenant-ID header |
| **HMAC Required** | All secret API keys (`sF`/`tB`) require HMAC validation |
| **Rate Limit per Key** | Rate limits enforced per API key, not per IP |
| **Immutable Audit** | Audit logs use append-only event store |
| **Emergency Revocation** | JWT/API key revocation triggers Redis cache purge |

---

## Replay Protection

### Idempotency Keys
- All mutation requests require `Idempotency-Key` header
- Keys valid for 24 hours
- Prevents duplicate operations on network retry

### Token Rotation
- Refresh token rotation on every use
- Previous refresh tokens immediately invalidated
- Maximum 7-day refresh window

### Session Invalidation
- Logout invalidates current session + all refresh tokens
- Logout-all terminates all user sessions
- Password change triggers all session invalidation

---

## Threat Mitigation

| Threat | Mitigation |
|--------|------------|
| **Replay Attack** | Idempotency keys, nonce validation, token rotation |
| **JWT Compromise** | Short expiration (15min), revocation list, emergency rotation |
| **API Key Leakage** | Secret keys have HMAC, rotation grace period, rate limiting |
| **Tenant Isolation Breach** | API-key-centric tenant resolution, query filtering |
| **Provider Compromise** | Provider abstraction, audit logging, webhook verification |

---

## Audit & Compliance

### Immutable Audit Log
- Event store in MySQL (append-only)
- Every mutation recorded with tenant context
- Retention: 7 years (configurable per tenant)

### Compliance Reports
- SOC 2 Type II ready
- GDPR data export (DSAR)
- Access logs exportable

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*
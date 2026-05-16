# UICP Terminology

## Metadata

```yaml
title: UICP Terminology
domain: documentation
owner: Docs Team
criticality: MEDIUM
runtime-impact: LOW
security-impact: LOW
queue-impact: LOW
provider-impact: LOW
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on: []
related-docs:
  - glossary.md
  - architecture-summary.md
related-queues: []
related-services: []
related-providers: []
related-runtime-states: []
related-threat-models: []
```

---

## Core Terms

### Identity & Access

| Term | Definition |
|------|------------|
| **Tenant** | Isolated organizational unit with its own users, quotas, and configuration |
| **User** | Individual identity within a tenant |
| **Identity** | Credential-linked account (email, phone, OAuth) belonging to a user |
| **Membership** | Association between a user and a tenant |
| **Actor** | Current user context for multi-actor sessions |
| **Session** | Authenticated state stored in Redis with replay protection |
| **API Key** | ULID-based credential for tenant resolution (uF/sF/pB/tB prefix) |
| **Publishable Key** | Client-safe key (uF/pB prefix) for frontend use |
| **Secret Key** | Server-safe key (sF/tB prefix) requiring HMAC validation |

### Authentication

| Term | Definition |
|------|------------|
| **Unified Auth** | Single authentication entry point supporting multiple methods |
| **Auth Method** | Password, OTP, Magic Link, OAuth, Passkey |
| **Credential** | Proof of identity (password, API key, JWT) |
| **State Token** | Base64-encoded authentication state for session resumption |
| **Idempotency Key** | Unique key preventing duplicate mutations |
| **Refresh Token** | Long-lived token for obtaining new access tokens |
| **Access Token** | Short-lived JWT with user identity and tenant context |

### Authorization

| Term | Definition |
|------|------------|
| **Role** | Named collection of permissions |
| **Permission** | Granular action allowance (e.g., `user:read`) |
| **Policy** | ABAC rule set with conditions |
| **JIT Role** | Just-in-time role activation with expiration |

### Communication

| Term | Definition |
|------|------------|
| **Provider** | External service for email/SMS delivery |
| **Provider Router** | Selection logic choosing optimal provider |
| **Template** | Dynamic message structure with variables |
| **Delivery** | Message dispatch attempt with status tracking |
| **Lineage** | Complete trace of message lifecycle |

### Platform Operations

| Term | Definition |
|------|------------|
| **Region** | Geographic deployment zone |
| **Geo-Routing** | Country/region-based traffic routing |
| **Failover** | Automatic switch to backup region/provider |
| **Incident** | Operational issue requiring response |
| **Chaos Experiment** | Controlled failure injection for resilience testing |

---

## Abbreviations

| Abbreviation | Full Form |
|--------------|-----------|
| UICP | Universal Identity & Communication Platform |
| CQRS | Command Query Responsibility Segregation |
| RBAC | Role-Based Access Control |
| ABAC | Attribute-Based Access Control |
| JIT | Just-in-Time |
| HMAC | Hash-based Message Authentication Code |
| ULID | Universally Unique Lexicographically Sortable Identifier |
| JWT | JSON Web Token |
| JWKS | JSON Web Key Set |
| OTP | One-Time Password |
| MFA | Multi-Factor Authentication |
| DSAR | Data Subject Access Request |
| DLQ | Dead Letter Queue |
| SLO | Service Level Objective |
| SLA | Service Level Agreement |

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*
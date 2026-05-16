# UICP Capabilities Matrix

## Metadata

```yaml
title: UICP Capabilities Matrix
domain: platform
owner: Product Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - product-overview.md
  - architecture-summary.md
related-docs:
  - trust-model-summary.md
  - runtime-summary.md
related-queues:
  - email-delivery
  - sms-delivery
  - otp-fastlane
related-services:
  - auth-service
  - communication-service
  - api-key-service
related-providers:
  - twilio
  - sendgrid
  - aws-ses
related-runtime-states:
  - running
  - degraded
related-threat-models:
  - provider-outage
  - replay-attack
```

---

## Feature Comparison by Tier

| Capability | Community | Business | Enterprise |
|------------|-----------|----------|------------|
| **Identity & Access** | | | |
| Unified Auth (password, OTP, magic link) | ✅ | ✅ | ✅ |
| OAuth 2.0 (Google, GitHub, Apple, Microsoft) | ✅ | ✅ | ✅ |
| Passkey/FIDO2 | ❌ | ✅ | ✅ |
| API Keys (ULID-based) | 10 | 100 | Unlimited |
| Multi-Factor Authentication | ❌ | ✅ | ✅ |
| Session Management | Basic | Advanced | Advanced + device management |
| Role-Based Access Control (RBAC) | ✅ | ✅ | ✅ |
| Attribute-Based Access (ABAC) | ❌ | ❌ | ✅ |
| **Communication** | | | |
| Email Delivery | 1 provider | 3 providers | All providers |
| SMS Delivery | 1 provider | 3 providers | All providers |
| OTP/2FA Fast Lane | ❌ | ✅ | ✅ |
| Webhooks | Basic | Advanced | Advanced + retry logic |
| Templates | 10 | 100 | Unlimited |
| **Platform** | | | |
| Multi-Tenant Isolation | ✅ | ✅ | ✅ |
| Tenant Quotas | ❌ | ✅ | ✅ |
| Tenant Migration | ❌ | ❌ | ✅ |
| Multi-Region | ❌ | ❌ | ✅ |
| Geo-Routing | ❌ | ❌ | ✅ |
| **Security** | | | |
| Zero-Trust Architecture | ✅ | ✅ | ✅ |
| Replay Protection | ✅ | ✅ | ✅ |
| Threat Intelligence | ❌ | Basic | Advanced |
| Vulnerability Scanning | ❌ | ❌ | ✅ |
| Audit Logs | 30 days | 1 year | 7 years |
| Compliance Reports | ❌ | SOC 2 | SOC 2, ISO 27001, GDPR |
| **Observability** | | | |
| Health Checks | ✅ | ✅ | ✅ |
| Basic Metrics | ✅ | ✅ | ✅ |
| Advanced Metrics | ❌ | ✅ | ✅ |
| Distributed Tracing | ❌ | ✅ | ✅ |
| AI-Assisted Debugging | ❌ | ❌ | ✅ |
| **Support** | | | |
| SLA | Best-effort | 99.9% | 99.99% |
| Support Hours | Community | 8x5 | 24x7 |
| Dedicated Account Manager | ❌ | ❌ | ✅ |
| Priority Ticket | ❌ | ✅ | ✅ |

---

## Feature Status Legend

| Status | Meaning |
|--------|---------|
| ✅ | Available - General Availability |
| 🏗️ | Roadmap - Planned for future |
| ❌ | Not available in this tier |
| Beta | Available - Beta testing |
| Deprecated | Being phased out |

---

## Capability Detail

### Identity & Access

| Capability | Description | Priority |
|------------|-------------|----------|
| Unified Auth | Single entry point for all auth methods | P0 - Critical |
| API Key Management | ULID-based dual-key system with HMAC | P0 - Critical |
| Session Management | Redis-backed with replay protection | P0 - Critical |
| MFA/2FA | OTP, email, SMS, authenticator app | P1 - High |
| Passkey | FIDO2/WebAuthn passwordless | P2 - Medium |
| OAuth Integration | Google, GitHub, Apple, Microsoft | P1 - High |
| JIT Access | Just-in-time role activation | P2 - Medium |

### Communication

| Capability | Description | Priority |
|------------|-------------|----------|
| Email Routing | Provider-agnostic with failover | P0 - Critical |
| SMS Routing | Multi-provider with smart selection | P0 - Critical |
| OTP Fast Lane | High-priority queue for 2FA | P0 - Critical |
| Template Management | Dynamic templates with variables | P1 - High |
| Webhook Processing | Async processing with retry | P1 - High |
| Provider Health | Real-time provider status | P2 - Medium |

### Platform Operations

| Capability | Description | Priority |
|------------|-------------|----------|
| Tenant Management | CRUD, migration, cloning | P0 - Critical |
| Quota Management | Per-tenant limits | P1 - High |
| Multi-Region | Regional failover | P2 - Medium |
| Geo-Routing | Country-based routing | P2 - Medium |
| Impersonation | Admin session takeover | P2 - Medium |

### Security & Compliance

| Capability | Description | Priority |
|------------|-------------|----------|
| Audit Logging | Immutable event store | P0 - Critical |
| Threat Detection | Anomaly detection | P1 - High |
| Vulnerability Scanning | Security assessments | P2 - Medium |
| DSAR | GDPR data requests | P1 - High |
| Consent Management | User consent tracking | P2 - Medium |

---

## Operational Constraints

| Resource | Community | Business | Enterprise |
|----------|-----------|----------|------------|
| API Calls/Month | 10,000 | 1,000,000 | Unlimited |
| Storage (GB) | 1 | 100 | Unlimited |
| Users | 100 | 10,000 | Unlimited |
| Domains | 1 | 10 | Unlimited |
| Rate Limit | 100/min | 1000/min | Custom |
| Concurrent Sessions | 10 | 100 | Unlimited |

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*
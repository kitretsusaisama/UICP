# UICP Product Overview

## Metadata

```yaml
title: UICP Product Overview
domain: platform
owner: Product Team
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
  - vision.md
  - mission.md
related-docs:
  - architecture-summary.md
  - capabilities-matrix.md
related-queues:
  - email-delivery
  - sms-delivery
  - otp-fastlane
related-services:
  - api-gateway
  - auth-service
  - communication-service
  - tenant-service
related-providers:
  - twilio
  - sendgrid
  - aws-ses
  - postmark
related-runtime-states:
  - running
  - degraded
  - scaling
related-threat-models:
  - replay-attack
  - jwt-compromise
  - provider-outage
  - redis-degradation
```

---

## Product Description

UICP (Universal Identity & Communication Platform) is an enterprise-grade, API-key-centric multi-tenant identity and communication platform built on hexagonal architecture with CQRS patterns.

---

## Target Personas

### 1. Enterprise CTOs
- **Concern**: Security, compliance, vendor lock-in
- **Value**: Zero-trust, tenant isolation, provider abstraction

### 2. Platform Engineers
- **Concern**: Scalability, reliability, debugging
- **Value**: Queue-first, AI-native, dependency graphs

### 3. Application Developers
- **Concern**: Integration speed, documentation quality
- **Value**: Unified auth SDK, comprehensive API docs

### 4. DevOps/SRE
- **Concern**: Observability, incident response, automation
- **Value**: OpenTelemetry, AI-assisted debugging, runbooks

---

## Core Products

### Identity & Access Management (IAM)
| Feature | Description |
|---------|-------------|
| Unified Auth | Single entry point for password, OTP, magic link, OAuth, passkey |
| API Key Management | ULID-based dual-key system (publishable + secret) |
| Session Management | Redis-backed sessions with replay protection |
| Role-Based Access | Policy-based authorization with ABAC support |
| Multi-Tenant Isolation | API-key-centric tenant resolution |

### Communication Fabric
| Feature | Description |
|---------|-------------|
| Email Delivery | Provider-agnostic routing with automatic failover |
| SMS Delivery | Multi-provider SMS with smart selection |
| OTP/2FA | High-priority queue for fastlane OTP delivery |
| Webhooks | Async webhook processing with retry logic |
| Templates | Dynamic template management |

### Platform Operations
| Feature | Description |
|---------|-------------|
| Multi-Region | Regional failover and geo-routing |
| Governance | Identity, roles, policies, audit |
| Security | Threat intel, vulnerability scanning, risk scoring |
| Resilience | Circuit breakers, chaos engineering, incidents |

---

## Feature Comparison

| Feature | Community | Business | Enterprise |
|---------|-----------|----------|------------|
| Tenants | 1 | 10 | Unlimited |
| API Keys | 10 | 100 | Unlimited |
| Monthly API Calls | 10K | 1M | Unlimited |
| Email Providers | 1 | 3 | All |
| Multi-Region | ❌ | ❌ | ✅ |
| Dedicated Support | ❌ | 8x5 | 24x7 |
| SLA | Best-effort | 99.9% | 99.99% |

---

## Integration Options

### SDKs
- **JavaScript/TypeScript** — `@uicp/sdk` (primary)
- **Python** — `uicp-python` (beta)
- **Go** — `uicp-go` (planned)

### Direct API
- **REST API** — Full CRUD + async operations
- **GraphQL** — Query flexibility (planned)
- **Webhooks** — Event-driven integration

### Infrastructure
- **CLI** — `uicpctl` for management
- **Terraform** — IaC for platform setup
- **Kubernetes** — Helm charts available

---

## Getting Started

```bash
# 1. Install CLI
npm install -g @uicp/cli

# 2. Initialize project
uicp init my-project

# 3. Create tenant
uicp tenants create --name "My Company"

# 4. Generate API keys
uicp api-keys create --tenant <tenant-id>

# 5. Make first call
curl -H "Authorization: Bearer <api-key>" https://api.uicp.dev/v1/users/me
```

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*
# UICP - Universal Identity & Communication Platform

## Metadata

```yaml
title: UICP Platform Overview
domain: platform
owner: Platform Team
criticality: CRITICAL
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-15
```

---

## Executive Summary

UICP (Universal Identity & Communication Platform) is an enterprise-grade, API-key-centric multi-tenant identity and communication platform built on event-driven architecture. It provides authentication, authorization, session management, and communication services for organizations requiring tenant isolation, replay-safe operations, and provider-agnostic communication routing.

---

## Platform Capabilities

| Capability | Status | Description |
|------------|--------|-------------|
| **Multi-Tenant Identity** | ✅ GA | API-key-centric tenant resolution |
| **Unified Authentication** | ✅ GA | Password, OTP, Magic Link, OAuth, Passkey |
| **Session Management** | ✅ GA | Redis-backed session store with replay protection |
| **Communication Fabric** | ✅ GA | Provider-agnostic email/SMS routing |
| **Queue-First Architecture** | ✅ GA | BullMQ-based async processing |
| **Zero-Trust Security** | ✅ GA | HMAC validation, replay prevention |
| **Multi-Region** | 🏗️ Roadmap | Regional failover support |
| **Smart Tuning** | 🏗️ Roadmap | Adaptive provider scoring |

---

## Architecture Principles

1. **Queue-First Design** - All external operations flow through queues for reliability
2. **Provider Abstraction** - Single interface for multiple email/SMS providers
3. **Replay-Safe Operations** - Idempotency keys prevent duplicate processing
4. **API-Key Centric** - Tenant context derived from credentials, not headers
5. **Zero-Trust** - Every request validated, no implicit trust

---

## Runtime Characteristics

- **Language**: TypeScript (Node.js/NestJS)
- **Database**: MySQL 8.0+ (event store, audit log, lineage)
- **Cache**: Redis 6.0+ (sessions, rate limits, provider routing)
- **Queue**: BullMQ (async processing, retries, dead letters)
- **Observability**: OpenTelemetry, structured logging

---

## Quick Links

| Section | Purpose |
|---------|---------|
| [Architecture](./01-architecture/system-architecture.md) | System design source of truth |
| [Runtime](./02-runtime/request-lifecycle.md) | Request processing flow |
| [Authentication](./03-auth/auth-overview.md) | IAM and auth flows |
| [Communication](./04-communication/communication-overview.md) | Provider routing |
| [Security](./05-security/zero-trust-model.md) | Security model |
| [API Reference](./07-api/authentication.md) | API contracts |
| [AI Context](./13-ai-context/system-summary.md) | Machine-readable summary |
| [Knowledge Graph](./14-knowledge-graph/services.graph.json) | Topology definitions |

---

## Support Matrix

| Support Tier | SLA | Contact |
|--------------|-----|---------|
| Enterprise | 24x7 | enterprise@uicp.example |
| Business | 8x5 | support@uicp.example |
| Developer | Community | docs@uicp.example |

---

## Version

- **Current**: 1.0.0
- **Minimum Node**: 18+
- **Minimum MySQL**: 8.0+
- **Minimum Redis**: 6.0+

---

*This document is part of the UICP Engineering Intelligence Layer.*
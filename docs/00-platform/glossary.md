# UICP Glossary

## Metadata

```yaml
title: UICP Glossary
domain: documentation
owner: Docs Team
criticality: LOW
runtime-impact: LOW
security-impact: LOW
queue-impact: LOW
provider-impact: LOW
tenant-impact: LOW
ai-ingestable: true
review-cycle: annual
last-reviewed: 2026-05-16
depends-on:
  - terminology.md
related-docs:
  - architecture-summary.md
  - runtime-summary.md
related-queues: []
related-services: []
related-providers: []
related-runtime-states: []
related-threat-models: []
```

---

## A

**API Gateway** — Entry point for all HTTP requests, handles authentication and routing.

**API Key** — ULID-based credential for tenant identification. Prefix determines type: uF (live publishable), sF (live secret), pB (dev publishable), tB (dev secret).

**Append-Only** — Data structure that only allows new records, preventing modification or deletion.

---

## B

**Bearer Token** — HTTP Authorization header value containing credentials (JWT or API key).

**BullMQ** — Redis-based queue system for async job processing with retry logic.

---

## C

**Circuit Breaker** — Pattern that prevents cascading failures by stopping requests to failing services.

**CQRS** — Command Query Responsibility Segregation. Separate models for reading and writing data.

---

## D

**Dead Letter Queue (DLQ)** — Queue for failed jobs that cannot be retried.

**Dependency Graph** — Visual representation of service relationships for impact analysis.

**Domain Resolution** — Process of deriving tenant context from credentials.

---

## E

**Event Store** — Append-only database storing all state changes as events.

---

## F

**Failover** — Automatic switching to backup when primary fails.

---

## G

**Geo-Routing** — Traffic routing based on geographic location.

---

## H

**HMAC** — Hash-based Message Authentication Code for API key validation.

**Hexagonal Architecture** — Pattern separating core logic from infrastructure through ports and adapters.

---

## I

**Idempotency** — Property where repeated operations produce the same result.

**Impersonation** — Admin capability to assume another user's session.

---

## J

**JWT** — JSON Web Token. Signed token containing user claims.

**JIT Role** — Just-in-Time role activation with automatic expiration.

**JWKS** — JSON Web Key Set. Public keys for JWT verification.

---

## L

**Lineage** — Complete trace of a request's path through the system.

---

## M

**Membership** — User's association with a tenant.

---

## O

**OAuth 2.0** — Authorization framework for delegated access.

**OTP** — One-Time Password. Single-use code for authentication.

---

## P

**Passkey** — FIDO2/WebAuthn credential for passwordless authentication.

**Policy** — ABAC rule set defining access conditions.

**Provider** — External service (email/SMS) integrated via abstraction layer.

**Provider Router** — Logic for selecting optimal provider based on latency, cost, health.

---

## Q

**Queue-First** — Architecture pattern where all external operations go through async queues.

---

## R

**Rate Limiting** — Controlling request frequency per API key or tenant.

**RBAC** — Role-Based Access Control.

**Replay Attack** — Malicious reuse of a captured valid request.

**Runtime** — Execution environment (Node.js/NestJS).

---

## S

**Secret Key** — API key requiring HMAC validation (sF/tB prefix).

**Session** — Authenticated state stored in Redis.

---

## T

**Tenant** — Isolated organizational unit.

**Tenant Resolution** — Deriving tenantId from API key, JWT, or session.

**Token Rotation** — Automatic refresh of expired tokens with invalidation of old ones.

---

## U

**ULID** — Universally Unique Lexicographically Sortable Identifier.

**Unified Auth** — Single authentication entry point supporting multiple methods.

---

## Z

**Zero-Trust** — Security model requiring explicit verification for every request.

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*
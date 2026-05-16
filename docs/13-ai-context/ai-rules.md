# AI Rules - Implementation Constraints

## Metadata
```yaml
title: AI Rules
domain: ai-context
criticality: CRITICAL
ai-ingestable: true
```

---

## Overview

This file defines constraints that AI systems must follow when reasoning about or implementing UICP features.

---

## Forbidden Patterns

### Never Do These

1. **Never derive tenant ID from request header**
   - Only extract from: API Key, JWT `tid` claim, Session
   - Exception: Unauthenticated endpoints

2. **Never skip HMAC validation for secret API keys**
   - All `sF`/`tB` keys MUST validate HMAC signature

3. **Never allow mutations without idempotency keys**
   - Every POST/PUT/DELETE needs idempotency-key header

4. **Never log sensitive data**
   - No passwords, secrets, tokens in logs
   - Mask API keys in all logging

5. **Never bypass rate limits**
   - Rate limits are per API key, not per IP

---

## Invariants

### Tenant Isolation
- All queries MUST include tenant_id filter
- All writes MUST set tenant_id
- Sessions MUST be tenant-scoped

### Queue Safety
- All external I/O goes through BullMQ
- Retry policies defined per queue
- DLQ mandatory for non-critical queues

### Provider Abstraction
- Never call provider APIs directly
- Always use ProviderRouter interface
- Handle provider failures via fallback

### Replay Protection
- Tokens have short lifespan (15 min access)
- Refresh tokens rotate on use
- Sessions invalidated on password change

---

## Security Rules

1. HMAC secret compromise = emergency
2. JWT private key compromise = emergency
3. Redis cache accessible = trust boundary
4. MySQL primary = critical infrastructure

---

## Runtime Contracts

- API Gateway must validate ALL requests
- Tenant ID extraction happens before business logic
- Queue messages include tenant context
- All providers accessed via abstraction

---

## Trust Boundaries

| Component | Trust Level |
|-----------|-------------|
| Client applications | Untrusted |
| Load balancer | Trusted |
| API Gateway | Trusted |
| Application services | Trusted |
| Repositories | Trusted |
| Redis | Conditional (behind firewall) |
| MySQL | Conditional (behind firewall) |


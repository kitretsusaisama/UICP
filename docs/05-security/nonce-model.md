# Nonce Model

## Metadata
```yaml
title: Nonce Model
domain: security
owner: Security Team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: NONE
provider-impact: NONE
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/replay-protection.md
  - 05-security/threat-model.md
related-docs:
  - 05-security/request-signing.md
  - 16-failure-models/replay-attacks.md
related-queues: []
related-services:
  - NonceValidator
  - RedisCache
related-runtime-states:
  - nonce-unused
  - nonce-used
  - nonce-expired
```

---

## Executive Summary

Nonces (number used once) prevent request replay attacks by ensuring each authenticated request is unique. UICP uses ULID-based nonces stored in Redis with configurable TTL.

---

## Nonce Specification

### Format

```
Type: ULID (Universally Unique Lexicographically Sortable Identifier)
Length: 26 characters
Example: 01ARZ3NDEKTSV4RRFFQ69G5FAV
```

### Properties

| Property | Value |
|----------|-------|
| Entropy | 80 bits |
| Collision probability | 1 in 2^80 |
| Lexicographically sortable | Yes |
| Time-based component | 48 bits |
| Random component | 80 bits |

---

## Nonce Validation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                   NONCE VALIDATION FLOW                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CLIENT                         SERVER                          │
│    │                              │                              │
│    │  1. Generate ULID nonce      │                              │
│    │  2. Include in request      │                              │
│    │─────────────────────────────▶│                              │
│    │                              │                              │
│    │                      ┌───────┴───────┐                     │
│    │                      │ 3. Extract    │                     │
│    │                      │ nonce from    │                     │
│    │                      │ header        │                     │
│    │                      └───────┬───────┘                     │
│    │                              │                              │
│    │                              ▼                              │
│    │                      ┌───────────────┐                     │
│    │                      │ 4. Check Redis│                     │
│    │                      │ EXISTS        │                     │
│    │                      │ nonce:{tid}:  │                     │
│    │                      │ {akid}:{hash} │                     │
│    │                      └───────────────┘                     │
│    │                              │                              │
│    │                      ┌───────┴───────┐                     │
│    │                      │ 5. Result     │                     │
│    │                      └───────┬───────┘                     │
│    │                ┌─────────────┼─────────────┐              │
│    │                ▼             ▼             ▼              │
│    │           ┌─────────┐  ┌──────────┐  ┌─────────┐        │
│    │           │ EXISTS  │  │ NOT EX   │  │ ERROR   │        │
│    │           │ (replay)│  │ (valid)  │  │ (fail)  │        │
│    │           └────┬────┘  └────┬─────┘  └────┬────┘        │
│    │                │            │             │              │
│    │                ▼            ▼             ▼              │
│    │          ┌─────────┐ ┌─────────┐  ┌─────────┐          │
│    │          │ REJECT  │ │ STORE   │  │ REJECT  │          │
│    │          │ 401     │ │ nonce   │  │ 500     │          │
│    │          └─────────┘ │ with    │  └─────────┘          │
│    │                        │ TTL     │                      │
│    │                        └─────────┘                      │
│    │                              │                              │
│    │◀─────────────────────────────│                              │
│    │     6. Return response        │                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation

### Redis Key Structure

```
Key: nonce:{tenantId}:{apiKeyId}:{nonceHash}
TTL: 3600 seconds (configurable)
Value: 1 (exists marker)
```

### Hash Algorithm

```typescript
function hashNonce(nonce: string): string {
  // Use SHA-256 to create fixed-length key component
  return sha256(nonce).substring(0, 16);
}
```

### Validation Code

```typescript
async function validateNonce(
  tenantId: string,
  apiKeyId: string,
  nonce: string
): Promise<NonceValidationResult> {
  // 1. Validate nonce format
  if (!nonce || !ulid.isValid(nonce)) {
    return { valid: false, reason: 'Invalid nonce format' };
  }

  // 2. Generate Redis key
  const key = `nonce:${tenantId}:${apiKeyId}:${hashNonce(nonce)}`;

  // 3. Check if nonce exists
  const exists = await redis.exists(key);

  if (exists) {
    // Nonce already used - replay attack detected
    logger.warn('Replay attempt detected', {
      tenantId,
      apiKeyId,
      nonce: nonce.substring(0, 8) + '...'
    });
    return { valid: false, reason: 'Nonce already used' };
  }

  // 4. Store nonce with TTL
  await redis.setex(key, config.nonceTtl, '1');

  return { valid: true };
}
```

---

## Configuration

| Parameter | Default | Environment Variable |
|-----------|---------|---------------------|
| nonce_ttl | 3600s | APP_NONCE_TTL |
| nonce_required | true (write ops) | APP_NONCE_REQUIRED |
| nonce_check_enabled | true | APP_NONCE_CHECK_ENABLED |

---

## Failure Modes

| Mode | Impact | Recovery |
|------|--------|----------|
| Redis unavailable | Auth requests fail | Fail closed (reject) for writes |
| Nonce cache full | Old nonces evicted early | Increase TTL or memory |
| Duplicate nonce accepted | Duplicate request processed | Manual audit, key rotation |
| Clock skew | Valid nonces rejected | Adjust timestamp tolerance |

---

## Monitoring

| Metric | Alert |
|--------|-------|
| nonce_replay_total | > 10/min |
| nonce_validation_failures | > 50/min |
| nonce_redis_errors | > 5/min |

---

## Related Documents

- `05-security/replay-protection.md`
- `05-security/request-signing.md`
- `16-failure-models/replay-attacks.md`
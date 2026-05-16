# API Key Runtime

## Metadata
```yaml
title: API Key Runtime Architecture
domain: authentication
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - runtime-context.md
  - domain-resolution.md
related-docs:
  - api-key-auth-design.md
  - ADR-001-api-key-runtime.md
  - zero-trust-model.md
related-queues:
  - audit-logging
related-services:
  - api-gateway
  - api-key-service
related-runtime-states:
  - running
  - degraded
related-threat-models:
  - api-key-compromise
  - replay-attacks
```

---

## Overview

The API key runtime provides tenant-scoped authentication without header dependencies. Keys embed tenant context and are validated cryptographically, enabling true zero-trust authentication.

---

## Key Format

### ULID-Based Dual Key System

UICP uses ULID-based keys with publishable/secret variants:

```
{prefix}{ULID26}{HMAC44?}
```

| Prefix | Type | Environment | Usage |
|--------|------|--------------|-------|
| `uF` | Publishable | Live | Client-side use (frontend) |
| `sF` | Secret | Live | Server-side use (backend) |
| `pB` | Publishable | Dev | Development/testing |
| `tB` | Secret | Dev | Development/testing |

**Example:**
- Live publishable: `uF01ARZ3NDEKTSV4RRFFQ69G7FAK`
- Live secret: `sF01ARZ3NDEKTSV4RRFFQ69G7FAKk1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1`

---

## Key Generation

### Generation Flow

```typescript
async function generateApiKey(input: CreateApiKeyInput): Promise<CreateApiKeyOutput> {
  // 1. Generate ULID
  const ulid = ulid(); // 26 characters

  // 2. Determine prefix based on env and type
  const prefix = input.env === 'dev'
    ? (input.type === 'publishable' ? 'pB' : 'tB')
    : (input.type === 'publishable' ? 'uF' : 'sF');

  // 3. Create publishable key
  const publishableKey = `${prefix}${ulid}`;

  // 4. If secret key, generate HMAC
  let secretKey = null;
  if (input.type === 'secret') {
    const hmac = crypto
      .createHmac('sha256', API_KEY_HMAC_SECRET)
      .update(publishableKey)
      .digest('base64')
      .slice(0, 44);
    secretKey = `${publishableKey}${hmac}`;
  }

  // 5. Store key in database
  const apiKey = await this.apiKeyRepository.save({
    tenantId: input.tenantId,
    key: input.type === 'secret' ? secretKey : publishableKey,
    name: input.name,
    scopes: input.scopes,
    status: 'active',
    // ... other fields
  });

  return { publishableKey, secretKey, apiKey };
}
```

---

## Key Validation

### Validation Flow

```typescript
async function validateApiKey(key: string): Promise<ApiKeyValidationResult> {
  // 1. Check prefix
  const prefix = key.slice(0, 2);
  if (!['uF', 'sF', 'pB', 'tB'].includes(prefix)) {
    return { isValid: false, error: { code: 'INVALID_PREFIX', message: 'Invalid key format' }};
  }

  // 2. Extract ULID
  const ulid = key.slice(2, 28);
  if (!isValidUlid(ulid)) {
    return { isValid: false, error: { code: 'INVALID_ULID', message: 'Invalid ULID' }};
  }

  // 3. If secret key, verify HMAC
  if (prefix === 'sF' || prefix === 'tB') {
    const hmac = key.slice(28);
    const expectedHmac = crypto
      .createHmac('sha256', API_KEY_HMAC_SECRET)
      .update(key.slice(0, 28))
      .digest('base64')
      .slice(0, 44);

    if (hmac !== expectedHmac) {
      return { isValid: false, error: { code: 'INVALID_HMAC', message: 'Signature verification failed' }};
    }
  }

  // 4. Look up key in repository
  const apiKey = await this.apiKeyRepository.findByKey(key);
  if (!apiKey) {
    return { isValid: false, error: { code: 'KEY_NOT_FOUND', message: 'Key not found' }};
  }

  // 5. Check status
  if (apiKey.status !== 'active') {
    return { isValid: false, error: { code: 'KEY_INACTIVE', message: 'Key is not active' }};
  }

  // 6. Check expiration
  if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
    return { isValid: false, error: { code: 'KEY_EXPIRED', message: 'Key has expired' }};
  }

  // 7. Check IP allowlist
  if (apiKey.ipAllowlist && apiKey.ipAllowlist.length > 0) {
    if (!apiKey.ipAllowlist.includes(clientIp)) {
      return { isValid: false, error: { code: 'IP_NOT_ALLOWED', message: 'IP not in allowlist' }};
    }
  }

  return { isValid: true, key: apiKey };
}
```

---

## Security Properties

### Cryptographic Properties

| Property | Implementation |
|----------|---------------|
| Uniqueness | ULID ensures globally unique keys |
| Unpredictability | 128-bit entropy in ULID |
| Integrity | HMAC-SHA256 prevents tampering |
| Non-repudiation | Signature validates origin |

### Environment Separation

- Dev keys (`pB`, `tB`) rejected in production
- Live keys (`uF`, `sF`) rejected in dev environments
- Cross-environment key usage blocked

---

## Rate Limiting

Per API key rate limits applied during validation:

```typescript
async function applyRateLimit(apiKey: ApiKeyEntity): Promise<void> {
  const key = `ratelimit:${apiKey.id}`;
  const current = await this.redis.incr(key);

  if (current === 1) {
    await this.redis.expire(key, 60); // 1 minute window
  }

  const limit = apiKey.rateLimit || 1000;
  if (current > limit) {
    throw new TooManyRequestsException('Rate limit exceeded');
  }
}
```

---

## Emergency Revocation

 Compromised keys immediately revoked:

```typescript
async function revokeKey(keyId: string): Promise<void> {
  // 1. Update database status
  await this.apiKeyRepository.update(keyId, { status: 'revoked' });

  // 2. Purge from Redis cache
  await this.redis.del(`apikey:${keyId}`);

  // 3. Invalidate active sessions using this key
  await this.redis.del(`ratelimit:${keyId}*`);

  // 4. Log revocation event
  await this.auditLog.log({
    action: 'api_key.revoked',
    keyId,
    timestamp: new Date(),
  });
}
```

---

## Related Documents

- `runtime-context.md`
- `domain-resolution.md`
- `trust-boundaries.md`
- `05-security/zero-trust-model.md`
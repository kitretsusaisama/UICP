# HMAC Validation

## Metadata
```yaml
title: HMAC Validation
domain: security
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: NONE
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/request-signing.md
  - 05-security/api-key-security.md
related-docs:
  - 05-security/zero-trust-model.md
  - 05-security/replay-protection.md
related-queues: []
related-services:
  - HmacValidator
  - SignatureValidator
related-runtime-states:
  - hmac-valid
  - hmac-invalid
  - hmac-missing
```

---

## Executive Summary

HMAC (Hash-based Message Authentication Code) validation provides cryptographic verification that requests have not been tampered with and originate from holders of the valid API key secret. UICP uses HMAC-SHA256 for all API key authenticated requests.

---

## Validation Process

### Step 1: Extract Components

```typescript
interface SignatureComponents {
  algorithm: string;      // 'hmac-sha256'
  signature: string;      // base64url encoded
  keyId?: string;         // optional, for key rotation
}

function parseSignatureHeader(header: string): SignatureComponents {
  const match = header.match(/^hmac-sha256=([A-Za-z0-9_-]+)$/);
  if (!match) {
    throw new ValidationError('Invalid signature format');
  }
  return {
    algorithm: 'hmac-sha256',
    signature: match[1]
  };
}
```

### Step 2: Retrieve Secret

```typescript
async function getSecretForKey(apiKeyId: string): Promise<string> {
  // Look up API key in cache first
  const cached = await redis.get(`apikey:${apiKeyId}:secret`);
  if (cached) {
    return cached;
  }

  // Fall back to database
  const apiKey = await apiKeyRepository.findById(apiKeyId);
  if (!apiKey || apiKey.status !== 'active') {
    throw new AuthenticationError('Invalid or inactive API key');
  }

  // Cache for performance
  await redis.setex(`apikey:${apiKeyId}:secret`, 3600, apiKey.secretHash);

  return apiKey.secretHash;
}
```

### Step 3: Compute Expected Signature

```typescript
function computeHmac(payload: string, secret: string): string {
  return crypto
    .createHmac('sha256', secret)
    .update(payload, 'utf8')
    .digest('base64url');
}
```

### Step 4: Constant-Time Comparison

```typescript
async function validateHmac(
  provided: string,
  expected: string
): Promise<boolean> {
  // Use timing-safe comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(provided),
    Buffer.from(expected)
  );
}
```

---

## Complete Validation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    HMAC VALIDATION FLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  INPUT: Request with X-Signature header                         │
│         │                                                        │
│         ▼                                                        │
│  ┌─────────────────────────────────────────┐                    │
│  │ 1. Parse signature header               │                    │
│  │    Extract algorithm and signature      │                    │
│  └─────────────────┬───────────────────────┘                    │
│                    │                                             │
│                    ▼                                             │
│  ┌─────────────────────────────────────────┐                    │
│  │ 2. Retrieve API key and secret          │                    │
│  │    from cache or database               │                    │
│  └─────────────────┬───────────────────────┘                    │
│                    │                                             │
│                    ▼                                             │
│  ┌─────────────────────────────────────────┐                    │
│  │ 3. Reconstruct signing payload           │                    │
│  │    method + path + timestamp + nonce     │                    │
│  │    + body hash                           │                    │
│  └─────────────────┬───────────────────────┘                    │
│                    │                                             │
│                    ▼                                             │
│  ┌─────────────────────────────────────────┐                    │
│  │ 4. Compute expected HMAC-SHA256         │                    │
│  │    hmac = HMAC-SHA256(payload, secret)  │                    │
│  └─────────────────┬───────────────────────┘                    │
│                    │                                             │
│                    ▼                                             │
│  ┌─────────────────────────────────────────┐                    │
│  │ 5. Timing-safe comparison               │                    │
│  │    constant-time-equal(provided, calc)  │                    │
│  └─────────────────┬───────────────────────┘                    │
│                    │                                             │
│           ┌───────┴───────┐                                     │
│           │               │                                      │
│           ▼               ▼                                      │
│      MATCH           NO MATCH                                    │
│           │               │                                      │
│           ▼               ▼                                      │
│    ┌──────────┐    ┌──────────────┐                            │
│    │ Return   │    │ Return 401   │                            │
│    │ valid    │    │ Invalid sig  │                            │
│    └──────────┘    └──────────────┘                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Considerations

### Timing Attacks Prevention

```typescript
// BAD: String comparison is not timing-safe
if (providedSignature === computedSignature) { } // VULNERABLE

// GOOD: Constant-time comparison
const provided = Buffer.from(providedSignature);
const computed = Buffer.from(computedSignature);
if (provided.length !== computed.length) {
  return false;
}
return crypto.timingSafeEqual(provided, computed);
```

### Secret Storage

| Aspect | Implementation |
|--------|----------------|
| Storage | bcrypt hash with cost factor 12 |
| Database | Encrypted at rest (AES-256) |
| Cache | Encrypted Redis connection |
| Memory | Cleared after validation |

---

## Failure Modes

| Failure | Impact | Mitigation |
|---------|--------|------------|
| Secret lookup fails | Authentication unavailable | Failover to database |
| HMAC computation timeout | Request timeout | Set timeout, fail fast |
| Timing attack succeeds | Signature forgery | Constant-time comparison |
| Secret compromised | Full tenant access | Emergency revocation |

---

## Testing HMAC Validation

```typescript
describe('HMAC Validation', () => {
  const secret = 'test-secret-key';
  const payload = 'POST\n/v1/queues\n1704067200\n01ARZ3NDEKTSV4RRFFQ69G5FAV\n';

  it('should validate correct HMAC', () => {
    const signature = computeHmac(payload, secret);
    const result = validateHmac(signature, computeHmac(payload, secret));
    expect(result).toBe(true);
  });

  it('should reject incorrect HMAC', () => {
    const result = validateHmac('wrong-signature', computeHmac(payload, secret));
    expect(result).toBe(false);
  });

  it('should use constant-time comparison', () => {
    // Test that timing is consistent regardless of match position
    const times = [];
    for (const sig of ['a' + 'b'.repeat(43), 'x' + 'y'.repeat(43)]) {
      const start = process.hrtime.bigint();
      validateHmac(sig, computeHmac(payload, secret));
      const end = process.hrtime.bigint();
      times.push(Number(end - start));
    }
    // Timing should be similar (within tolerance)
    expect(Math.abs(times[0] - times[1]) < 1000).toBe(true);
  });
});
```

---

## Related Documents

- `05-security/request-signing.md`
- `05-security/api-key-security.md`
- `05-security/zero-trust-model.md`
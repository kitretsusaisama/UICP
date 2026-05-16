# API Key Security

## Metadata
```yaml
title: API Key Security
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
  - 05-security/zero-trust-model.md
  - 05-security/threat-model.md
  - 05-security/replay-protection.md
related-docs:
  - 05-security/hmac-validation.md
  - 05-security/secret-management.md
  - 17-adrs/ADR-001-api-key-runtime.md
related-queues: []
related-services:
  - ApiKeyService
  - ApiKeyRepository
  - UnifiedAuthGuard
related-runtime-states:
  - key-generated
  - key-validated
  - key-revoked
  - key-expired
```

---

## Executive Summary

API keys provide programmatic access to UICP. This document covers key generation, validation, storage, and lifecycle management. UICP uses ULID-based dual key system with HMAC signature validation.

---

## Key Architecture

### Dual Key System

UICP implements two-key architecture for enhanced security:

```
┌─────────────────────────────────────────────────────────────────┐
│                      API KEY STRUCTURE                          │
├─────────────────────────────────────────────────────────────────┤
│  Public Key (client-facing)                                    │
│  Format: {prefix}{ULID26}                                       │
│  Example: uF01ARZ3NDEKTSV4RRFFQ69G5FAV                          │
│  Used in: X-API-Key header                                     │
├─────────────────────────────────────────────────────────────────┤
│  Secret Key (never shared)                                     │
│  Format: {ULID26}{HMAC-SHA256}                                 │
│  Example: 01ARZ3NDEKTSV4RRFFQ69G5FAV{44-char-hmac}             │
│  Used for: Request signature validation                        │
└─────────────────────────────────────────────────────────────────┘
```

### Key Prefix Meaning

| Prefix | Type | Purpose |
|--------|------|---------|
| uF | Full access | User API key with all permissions |
| pB | Production | Production-ready key |
| sF | Service | Service-to-service communication |
| tB | Testing | Test/sandbox environment |

---

## Key Generation

```typescript
async function generateApiKey(
  tenantId: string,
  permissions: string[],
  expiresAt?: Date
): Promise<ApiKey> {
  // 1. Generate ULID for key ID
  const keyId = ulid();

  // 2. Generate secret component (44 chars HMAC)
  const secret = crypto.randomBytes(32).toString('base64url');

  // 3. Construct full secret (stored hashed)
  const fullSecret = `${keyId}${secret}`;
  const secretHash = await bcrypt.hash(fullSecret, 12);

  // 4. Create key record
  const apiKey = {
    id: keyId,
    publicId: `uF${keyId.slice(0, 26)}`,
    tenantId,
    permissions,
    secretHash,
    createdAt: new Date(),
    expiresAt,
    status: 'active'
  };

  // 5. Store in database
  await apiKeyRepository.save(apiKey);

  // 6. Return public key + secret (ONE TIME ONLY)
  return {
    publicKey: `uF${keyId.slice(0, 26)}`,
    secret: `${keyId}${secret}`, // Show once!
    expiresAt
  };
}
```

---

## Key Validation Flow

```
Request with X-API-Key
         │
         ▼
┌─────────────────┐
│ Extract key ID  │
│ from public key │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Lookup key in   │
│ repository      │
└────────┬────────┘
         │
    ┌────┴────┐
    │ Found?  │
    └────┬────┘
    No   │   Yes
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌─────────────────┐
│ Reject│ │ Check status    │
└───────┘ └────────┬────────┘
                   │
              ┌────┴────┐
              │ Active? │
              └────┬────┘
              No  │  Yes
              ┌───┴───┐
              ▼       ▼
          ┌──────┐ ┌─────────────────┐
          │Reject│ │ Validate HMAC   │
          └──────┘ └────────┬────────┘
                            │
                       ┌────┴────┐
                       │ Valid?  │
                       └────┬────┘
                       No  │  Yes
                       ┌───┴───┐
                       ▼       ▼
                   ┌──────┐ ┌─────────────────┐
                   │Reject│ │ Check rate limit│
                   └──────┘ └────────┬────────┘
                                     │
                                ┌────┴────┐
                                │ Within? │
                                └────┬────┘
                                No  │  Yes
                                ┌───┴───┐
                                ▼       ▼
                            ┌──────┐ ┌─────────────────┐
                            │Reject│ │ Authenticate   │
                            └──────┘ └─────────────────┘
```

---

## HMAC Validation

For requests requiring signature validation:

```typescript
async function validateSignature(
  request: AuthenticatedRequest,
  apiKey: ApiKey
): Promise<boolean> {
  // 1. Reconstruct signing payload
  const payload = [
    request.method,
    request.path,
    request.headers['x-timestamp'],
    request.headers['x-nonce'] || '',
    sha256(request.body)
  ].join('\n');

  // 2. Calculate expected HMAC
  const expected = crypto
    .createHmac('sha256', apiKey.secretHash)
    .update(payload)
    .digest('base64url');

  // 3. Compare with provided signature
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(request.headers['x-signature'])
  );
}
```

---

## Key Storage Security

| Aspect | Implementation |
|--------|----------------|
| Secret hashing | bcrypt with cost factor 12 |
| Database encryption | AES-256 at rest |
| Key rotation | 90-day automatic rotation |
| Audit logging | All key operations logged |

---

## Emergency Revocation

```
Endpoint: POST /v1/tenant/api-keys/:id/revoke

Flow:
1. Validate requester has admin permissions
2. Set key status to 'revoked' in MySQL
3. Purge key from Redis cache
4. Invalidate all active sessions for this key
5. Log audit event with revoker identity
6. Send notification to tenant admin
```

---

## Related Documents

- `05-security/zero-trust-model.md`
- `05-security/threat-model.md`
- `05-security/hmac-validation.md`
- `17-adrs/ADR-001-api-key-runtime.md`
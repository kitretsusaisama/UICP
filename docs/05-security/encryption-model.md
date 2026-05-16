# Encryption Model

## Metadata
```yaml
title: Encryption Model
domain: security
owner: Security Team
criticality: CRITICAL
runtime-impact: MEDIUM
security-impact: CRITICAL
queue-impact: LOW
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/secret-management.md
  - 05-security/threat-model.md
related-docs:
  - 05-security/provider-secret-encryption.md
  - 05-security/zero-trust-model.md
related-queues: []
related-services:
  - EncryptionService
  - KeyManagementService
  - HsmService
related-runtime-states:
  - encrypted
  - decrypted
  - key-rotated
```

---

## Executive Summary

UICP implements encryption at rest and in transit to protect sensitive data. This document covers encryption algorithms, key management, and implementation details.

---

## Encryption Layers

### 1. Transport Layer (TLS)

| Aspect | Configuration |
|--------|---------------|
| Version | TLS 1.3 (TLS 1.2 fallback) |
| Cipher Suites | TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |
| Certificate | RSA 4096-bit or ECDSA P-384 |
| Pinning | Enabled for mobile clients |
| HSTS | Enabled, max-age 1 year |

### 2. Application Layer (Encryption at Rest)

```
┌─────────────────────────────────────────────────────────────────┐
│                ENCRYPTION AT REST ARCHITECTURE                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐        ┌──────────────┐        ┌─────────┐ │
│  │   Plaintext  │───────▶│ Encryption   │───────▶│ Cipher  │ │
│  │   Data       │        │ Service      │        │ Text    │ │
│  └──────────────┘        └───────┬───────┘        └────┬────┘ │
│                                  │                      │       │
│                                  ▼                      │       │
│                          ┌───────────────┐             │       │
│                          │  KMS / HSM    │◀────────────┘       │
│                          │  (DEK decrypt)│                    │
│                          └───────────────┘                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                      KEY HIERARCHY                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Master Key (HSM)                                              │
│       │                                                         │
│       ▼                                                         │
│  Key Encryption Key (KEK) - per environment                   │
│       │                                                         │
│       ▼                                                         │
│  Data Encryption Keys (DEK) - per tenant/resource             │
│       │                                                         │
│       ▼                                                         │
│  Encrypted Data                                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Types

| Type | Purpose | Storage |
|------|---------|---------|
| Master Key | Encrypt KEKs | HSM |
| KEK | Encrypt DEKs | KMS |
| DEK | Encrypt actual data | Encrypted in DB |

---

## Encryption Algorithms

### Data Encryption

```typescript
interface EncryptOptions {
  algorithm: 'AES-256-GCM';
  ivLength: 12;
  authTagLength: 16;
}

async function encrypt(plaintext: Buffer, dek: Buffer): Promise<EncryptedData> {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    algorithm: 'AES-256-GCM'
  };
}
```

### Key Derivation

```typescript
function deriveKey(masterKey: Buffer, context: string): Buffer {
  return crypto
    .createHmac('sha256', masterKey)
    .update(context)
    .digest();
}
```

---

## Data Classification

| Category | Examples | Encryption | Key Isolation |
|----------|----------|------------|---------------|
| Critical | API secrets, provider keys | AES-256-GCM | Per tenant |
| Sensitive | PII, user data | AES-256-GCM | Per tenant |
| Internal | Logs, metrics | AES-256 | Per environment |
| Public | Documentation | None | N/A |

---

## Implementation Patterns

### Column-Level Encryption

```typescript
@Entity()
export class ProviderCredential {
  @Column({ type: 'varchar', encrypted: true })
  apiKey: string;

  @Column({ type: 'varchar', encrypted: true })
  apiSecret: string;

  @Column({ type: 'varchar' })
  tenantId;
}
```

### Field-Level Encryption

```typescript
class SensitiveField {
  @Transform(value => encrypt(value), { to: 'database' })
  @Transform(value => decrypt(value), { to: 'class' })
  value: string;
}
```

---

## Key Rotation

### Automatic Rotation

```
Schedule:
- DEK: Every 90 days
- KEK: Every 365 days
- Master Key: Annually (HSM managed)

Process:
1. Generate new DEK
2. Re-encrypt all data with new DEK
3. Store new DEK encrypted with KEK
4. Archive old DEK (for decryption during recovery)
5. Update key metadata
```

### Rotation Implementation

```typescript
async function rotateDek(tenantId: string): Promise<void> {
  // 1. Generate new DEK
  const newDek = crypto.randomBytes(32);

  // 2. Encrypt with KEK
  const encryptedDek = await encryptWithKek(newDek);

  // 3. Store new DEK
  await dekStore.save(tenantId, encryptedDek, {
    rotatedAt: new Date(),
    status: 'active'
  });

  // 4. Re-encrypt tenant data (background job)
  await reEncryptTenantData(tenantId, newDek);
}
```

---

## Trust Boundaries

| Component | Encryption | Trust Level |
|-----------|------------|-------------|
| Client → Gateway | TLS 1.3 | UNTRUSTED → BOUNDARY |
| Gateway → App | TLS 1.3 | BOUNDARY → TRUSTED |
| App → Database | TLS + at-rest | TRUSTED → ISOLATED |
| Keys in Memory | Encrypted | TRUSTED |

---

## Related Documents

- `05-security/secret-management.md`
- `05-security/provider-secret-encryption.md`
- `05-security/zero-trust-model.md`
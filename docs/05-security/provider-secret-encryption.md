# Provider Secret Encryption

## Metadata
```yaml
title: Provider Secret Encryption
domain: security
owner: Platform Team
criticality: CRITICAL
runtime-impact: MEDIUM
security-impact: CRITICAL
queue-impact: LOW
provider-impact: HIGH
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/encryption-model.md
  - 05-security/secret-management.md
related-docs:
  - 05-security/encryption-model.md
  - 04-communication/provider-runtime.md
related-queues: []
related-services:
  - ProviderSecretService
  - EncryptionService
  - ProviderCredentialRepository
related-runtime-states:
  - secret-encrypted
  - secret-decrypted
  - secret-rotated
```

---

## Executive Summary

Provider secrets (API keys, tokens, credentials for email/SMS providers) are encrypted at rest and decrypted only at runtime when needed. This document covers the encryption model for provider credentials.

---

## Secret Classification

| Provider Type | Secrets | Sensitivity |
|---------------|---------|-------------|
| Email (SES, Resend, Mailgun) | API Key, SMTP credentials | CRITICAL |
| SMS (Twilio, Msg91) | Account SID, Auth Token | CRITICAL |
| WhatsApp (WhatsApp Business) | Phone Number ID, Token | CRITICAL |
| Voice (Vonage) | API Key, Application ID | CRITICAL |

---

## Encryption Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│            PROVIDER SECRET ENCRYPTION FLOW                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  STORAGE (at rest)                                              │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ tenant_id: "tenant_abc"                                 │  │
│  │ provider: "resend"                                      │  │
│  │ api_key_encrypted: "gAAAAABk..." (AES-256-GCM)         │  │
│  │ api_secret_encrypted: "gAAAAABk..."                    │  │
│  │ created_at: "2024-01-01"                               │  │
│  │ rotated_at: "2024-04-01"                               │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                  │
│  RUNTIME (decryption)                                          │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ 1. Load encrypted secret from DB                       │  │
│  │ 2. Retrieve DEK from key store                         │  │
│  │ 3. Decrypt with AES-256-GCM                            │  │
│  │ 4. Use for API calls                                   │  │
│  │ 5. Clear from memory immediately                       │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation

### Database Schema

```typescript
@Entity()
export class ProviderCredential {
  @PrimaryColumn()
  id: string;

  @Column()
  tenantId: string;

  @Column()
  provider: string;

  @Column({ type: 'varchar', encrypted: true })
  apiKey: string;

  @Column({ type: 'varchar', encrypted: true, nullable: true })
  apiSecret: string;

  @Column({ type: 'varchar', encrypted: true, nullable: true })
  webhookSecret: string;

  @Column({ type: 'varchar', nullable: true })
  encryptionKeyId: string;

  @Column()
  status: 'active' | 'rotating' | 'revoked';

  @Column()
  createdAt: Date;

  @Column()
  expiresAt: Date;
}
```

### Encryption Service

```typescript
@Injectable()
export class ProviderSecretEncryption {
  private dekCache: Map<string, Buffer> = new Map();

  async encrypt(plaintext: string, tenantId: string): Promise<EncryptedSecret> {
    // 1. Get or generate DEK for tenant
    const dek = await this.getDek(tenantId);

    // 2. Generate IV
    const iv = crypto.randomBytes(12);

    // 3. Encrypt
    const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    // 4. Return format
    return {
      ciphertext: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      keyId: this.getCurrentKeyId()
    };
  }

  async decrypt(encrypted: EncryptedSecret): Promise<string> {
    // 1. Get DEK
    const dek = await this.getDekByKeyId(encrypted.keyId);

    // 2. Decrypt
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      dek,
      Buffer.from(encrypted.iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(encrypted.authTag, 'base64'));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted.ciphertext, 'base64')),
      decipher.final()
    ]);

    return decrypted.toString('utf8');
  }

  private async getDek(tenantId: string): Promise<Buffer> {
    if (this.dekCache.has(tenantId)) {
      return this.dekCache.get(tenantId);
    }

    // Load from secure storage
    const dek = await this.keyManager.getDek(tenantId);
    this.dekCache.set(tenantId, dek);

    return dek;
  }
}
```

---

## Key Rotation

### Rotation Triggers

| Trigger | Timeline |
|---------|----------|
| Scheduled | Every 90 days |
| Provider request | Immediate |
| Security incident | Immediate |
| Tenant request | Immediate |

### Rotation Process

```
1. Generate new key material
2. Encrypt new secrets with new DEK
3. Store new encrypted secrets (keep old for rollback)
4. Update provider to use new credentials
5. Test provider connectivity
6. Mark old secrets as 'rotating'
7. Wait grace period (24 hours)
8. Delete old secrets
```

---

## Memory Security

```typescript
class SecureSecretUsage {
  async callProviderApi(credential: ProviderCredential): Promise<void> {
    // Decrypt secrets
    const apiKey = await this.encryption.decrypt(credential.apiKey);

    try {
      // Use secrets for API call
      await this.providerClient.send(apiKey, /* ... */);
    } finally {
      // CRITICAL: Clear sensitive data from memory
      apiKey.fill(0);  // Overwrite with zeros
    }
  }
}
```

---

## Trust Boundaries

| Layer | Encryption | Access |
|-------|------------|--------|
| Database | AES-256 at rest | Restricted to app |
| Key Manager | KEK encryption | HSM/KMS |
| Runtime | Decrypted in memory | Application only |

---

## Related Documents

- `05-security/encryption-model.md`
- `05-security/secret-management.md`
- `04-communication/provider-runtime.md`
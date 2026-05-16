# Secret Management

## Metadata
```yaml
title: Secret Management
domain: security
owner: DevOps Team
criticality: CRITICAL
runtime-impact: MEDIUM
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: HIGH
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/encryption-model.md
  - 05-security/api-key-security.md
related-docs:
  - 05-security/provider-secret-encryption.md
  - 05-security/credential-lineage.md
  - 02-runtime/cache-runtime.md
related-queues: []
related-services:
  - SecretManager
  - EncryptionService
  - KeyRotationService
related-runtime-states:
  - secret-stored
  - secret-rotated
  - secret-compromised
```

---

## Executive Summary

Secret management covers handling of all sensitive credentials: API keys, database passwords, provider secrets, encryption keys. UICP uses a layered approach with encryption at rest and automated rotation.

---

## Secret Categories

| Category | Examples | Storage | Rotation |
|----------|----------|---------|----------|
| Internal | DB password, Redis auth | Vault/Encrypted | 90 days |
| Provider | SMTP credentials, SMS API keys | Encrypted DB | Per provider |
| Tenant | Tenant-specific secrets | Tenant vault | Per tenant |
| Runtime | JWT signing keys | HSM/Vault | 24 hours |

---

## Secret Storage Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SECRET STORAGE LAYERS                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│  │   Application│    │   KMS        │    │  HSM         │     │
│  │   Code       │───▶│   (Encryption)│───▶│  (Key Store) │     │
│  └──────────────┘    └──────────────┘    └──────────────┘     │
│         │                   │                   │              │
│         ▼                   ▼                   ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│  │  Environment │    │  MySQL       │    │  Redis       │     │
│  │  Variables   │    │  (Encrypted) │    │  (ACL)       │     │
│  └──────────────┘    └──────────────┘    └──────────────┘     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Encryption at Rest

### Database Secrets

```typescript
// Secret stored encrypted in MySQL
@Entity()
export class ProviderSecret {
  @Column({ type: 'varchar', encrypted: true })
  apiKey: string;

  @Column({ type: 'varchar', encrypted: true })
  apiSecret: string;
}
```

**Algorithm**: AES-256-GCM with unique IV per encryption

### Key Derivation

```
Master Key (from KMS)
        │
        ▼
┌─────────────────┐
│ Derive DEK      │  DEK = HMAC-SHA256(masterKey, 'data-encryption')
│ (Data Enc Key)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Encrypt secret │  ciphertext = AES-GCM(DEK, secret, iv)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Store ciphertext│  EncryptedDEK + IV + ciphertext
└─────────────────┘
```

---

## Secret Injection

### Runtime Secret Loading

```typescript
@Injectable()
export class SecretLoader {
  async loadSecrets(): Promise<void> {
    // Load from environment (fallback)
    // Load from Vault (primary)
    // Load from KMS (encryption keys)

    for (const secret of requiredSecrets) {
      const value = await this.vault.get(secret.path);
      process.env[secret.envVar] = value;
    }
  }
}
```

### Startup Validation

```
┌─────────────────────────────────────────┐
│         APPLICATION STARTUP             │
├─────────────────────────────────────────┤
│ 1. Validate all required secrets exist │
│ 2. Test database connection            │
│ 3. Test Redis connection               │
│ 4. Verify encryption keys accessible   │
│ 5. If any check fails → FAIL STARTUP  │
└─────────────────────────────────────────┘
```

---

## Rotation Strategy

### Automatic Rotation

| Secret Type | Rotation Frequency | Method |
|-------------|-------------------|--------|
| JWT Signing | Every 24 hours | Rolling key in KMS |
| Database | Every 90 days | Managed by DBA |
| API Keys (tenant) | Every 90 days | User-initiated |
| Provider secrets | Per provider limits | Automated |

### Rotation Workflow

```
1. Generate new secret
2. Store new secret (keep old for rollback)
3. Update application to use new secret
4. Verify application health
5. Delete old secret (after grace period)
```

---

## Secret Recovery

### Backup and Restore

```
Encrypted secrets backed up daily:
- Database: Point-in-time recovery
- Vault: Snapshot export
- KMS: Key rotation logs

Recovery procedure:
1. Restore from backup
2. Re-encrypt with current KMS key
3. Verify application connectivity
```

### Compromise Response

```
If secret compromised:
1. Immediately rotate affected secret
2. Revoke all sessions using old secret
3. Audit access logs for compromise window
4. Notify affected tenants
5. Update security incident report
```

---

## Trust Boundaries

| Component | Access Level | Justification |
|-----------|--------------|---------------|
| Application | Decrypt | Runtime needs plaintext |
| KMS | Encrypt/Decrypt | Centralized key management |
| HSM | Key Storage | Hardware security module |
| Database | Encrypted storage | Encrypted at rest |

---

## Related Documents

- `05-security/encryption-model.md`
- `05-security/provider-secret-encryption.md`
- `05-security/credential-lineage.md`
# Communication Security

## Metadata
```yaml
title: Communication Security
domain: communication
owner: Security Team
criticality: HIGH
runtime-impact: HIGH
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - communication-overview.md
  - webhook-reconciliation.md
related-docs:
  - provider-runtime.md
  - delivery-lineage.md
  - suppression-system.md
related-queues:
  - security-audit
related-services:
  - SecurityValidator
  - CredentialManager
  - AuditLogger
  - EncryptionService
related-providers:
  - SES
  - Resend
  - Maileroo
  - Msg91
related-runtime-states:
  - security_validating
  - security_verified
  - security_blocked
  - security_audit_logged
related-threat-models:
  - Message injection
  - Credential theft
  - Data leakage
  - Sender spoofing
```

---

## Overview

Communication Security protects the messaging infrastructure against unauthorized access, data leakage, and injection attacks. It encompasses credential management, message validation, and audit logging.

---

## Credential Management

### Provider Credentials

Credentials are stored encrypted with key rotation:

```typescript
interface CredentialConfig {
  provider: string;
  credentialType: 'api_key' | 'oauth' | 'iam_role';
  encryptedSecret: string;
  keyVersion: number;
  rotationDueDate: Date;
  lastRotated: Date;
}

async function rotateProviderCredentials(provider: string): Promise<void> {
  const newCredentials = await generateNewCredentials(provider);

  // Encrypt with latest key
  const encrypted = await encryption.encrypt(
    newCredentials,
    await keyManager.getLatestKey()
  );

  await store.update(provider, {
    encryptedSecret: encrypted,
    keyVersion: currentVersion,
    lastRotated: new Date()
  });

  // Test new credentials before switching
  await providerAdapter.validateCredentials(newCredentials);
}
```

### Credential Storage

- Encrypted at rest using AES-256-GCM
- Key rotation every 90 days
- Access logging for all credential operations
- Separate encryption keys per environment

---

## Message Security

### Input Validation

```typescript
async function validateMessage(message: OutboundMessage): Promise<ValidationResult> {
  const errors: ValidationError[] = [];

  // Validate sender
  if (!isValidEmail(message.sender)) {
    errors.push({ field: 'sender', message: 'Invalid sender format' });
  }

  // Validate recipients
  for (const recipient of message.recipients) {
    if (!isValidEmail(recipient)) {
      errors.push({ field: 'recipients', message: `Invalid recipient: ${recipient}` });
    }
  }

  // Validate content
  if (containsSuspiciousContent(message.body)) {
    errors.push({ field: 'body', message: 'Suspicious content detected' });
  }

  return {
    valid: errors.length === 0,
    errors
  };
}
```

### Content Filtering

| Filter | Action |
|--------|--------|
| Malware attachments | Reject |
| Phishing URLs | Warn and redact |
| Sensitive data patterns | Redact |
| Excessive links | Rate limit |

---

## Sender Verification

### Email Authentication

All sending domains must implement:

```typescript
interface SenderVerification {
  domain: string;
  spf: {
    status: 'pass' | 'fail' | 'neutral';
    record: string;
  };
  dkim: {
    status: 'pass' | 'fail' | 'neutral';
    selector: string;
  };
  dmarc: {
    policy: 'none' | 'quarantine' | 'reject';
    alignment: 'pass' | 'fail';
  };
}
```

### Verification Process

1. Domain ownership confirmed via DNS
2. SPF record published
3. DKIM key configured
4. DMARC policy set
5. Continuous monitoring

---

## Audit Logging

### Logged Events

```typescript
interface AuditEvent {
  timestamp: Date;
  actor: string;
  action: string;
  resource: string;
  result: 'success' | 'failure';
  metadata: Record<string, any>;
}

// Events to log
const auditedActions = [
  'message.send',
  'message.cancel',
  'provider.credential.rotate',
  'template.create',
  'template.update',
  'suppression.add',
  'tenant.config.update'
];
```

### Log Integrity

- Append-only storage
- Cryptographic hash chain
- Immutable for 7 years
- Quarterly integrity verification

---

## TLS and Encryption

### In-Transit Encryption

| Connection | Protocol | Notes |
|------------|----------|-------|
| Client → UICP | TLS 1.3 | Required |
| UICP → Provider | TLS 1.2+ | Provider-specific |
| Webhook → UICP | TLS 1.3 | Certificate pin |

### At-Rest Encryption

- Database: AES-256
- Cache: AES-256
- Backups: AES-256-GCM

---

## Threat Detection

### Anomaly Detection

```typescript
interface AnomalyDetector {
  // Detect unusual patterns
  detectSendAnomalies(tenantId: string): Promise<AnomalyReport>;

  // Flag suspicious activity
  flagSuspiciousBehavior(event: SecurityEvent): boolean;
}

const anomalyThresholds = {
  messageVolume: {
    warning: 10000,  // messages/hour
    critical: 50000
  },
  failedAuth: {
    warning: 5,      // failures/hour
    critical: 20
  },
  unusualRecipients: {
    warning: 50,     # unique recipients/hour
    critical: 200
  }
};
```

---

## Related Documents

- `04-communication/communication-overview.md`
- `04-communication/webhook-reconciliation.md`
- `04-communication/delivery-lineage.md`
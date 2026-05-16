# Emergency Revocation

## Metadata
```yaml
title: Emergency Revocation
domain: security
owner: Security Operations
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: CRITICAL
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/api-key-security.md
  - 05-security/incident-response.md
related-docs:
  - 05-security/zero-trust-model.md
  - 05-security/credential-lineage.md
  - 17-adrs/ADR-001-api-key-runtime.md
related-queues: []
related-services:
  - RevocationService
  - SessionInvalidator
  - RedisCache
related-runtime-states:
  - active
  - revoking
  - revoked
```

---

## Executive Summary

Emergency revocation allows immediate invalidation of compromised credentials (API keys, sessions, tokens) to contain security incidents. This document covers revocation procedures, automation, and recovery.

---

## Revocation Types

| Type | Target | Speed | Use Case |
|------|--------|-------|----------|
| API Key Revocation | Single key | Immediate | Known compromised key |
| Tenant Revocation | All tenant keys | Immediate | Full tenant compromise |
| Session Revocation | User sessions | Immediate | Account takeover |
| Global Revocation | All credentials | Emergency only | Critical vulnerability |

---

## Revocation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                   EMERGENCY REVOCATION FLOW                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  REQUEST                    PROCESSING                          │
│  │                          │                                   │
│  │  ┌──────────────┐        │                                   │
│  │  │ Revoke API  │        │                                   │
│  │  │ Key or      │        │                                   │
│  │  │ Session     │        │                                   │
│  │  └──────┬───────┘        │                                   │
│  └─────────┼────────────────┘                                   │
│            │                                                    │
│            ▼                                                    │
│  ┌─────────────────────────────────┐                            │
│  │ 1. Validate permissions        │                            │
│  │    (must be admin or owner)    │                            │
│  └────────────┬───────────────────┘                            │
│               │                                                 │
│               ▼                                                 │
│  ┌─────────────────────────────────┐                            │
│  │ 2. Update database status       │                            │
│  │    status = 'revoked'          │                            │
│  │    revoked_at = NOW()          │                            │
│  │    reason = 'emergency'        │                            │
│  └────────────┬───────────────────┘                            │
│               │                                                 │
│               ▼                                                 │
│  ┌─────────────────────────────────┐                            │
│  │ 3. Purge Redis cache           │                            │
│  │    DEL api-key:{id}            │                            │
│  │    DEL nonce:*                 │                            │
│  │    DEL session:*               │                            │
│  └────────────┬───────────────────┘                            │
│               │                                                 │
│               ▼                                                 │
│  ┌─────────────────────────────────┐                            │
│  │ 4. Invalidate sessions         │                            │
│  │    DEL session:{tenantId}:*    │                            │
│  │    DEL token:{tenantId}:*      │                            │
│  └────────────┬───────────────────┘                            │
│               │                                                 │
│               ▼                                                 │
│  ┌─────────────────────────────────┐                            │
│  │ 5. Log audit event             │                            │
│  │    AUTH_KEY_REVOKED            │                            │
│  └────────────┬───────────────────┘                            │
│               │                                                 │
│               ▼                                                 │
│  ┌─────────────────────────────────┐                            │
│  │ 6. Notify tenant               │                            │
│  │    Email + In-app notification │                            │
│  └─────────────────────────────────┘                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation

### API Key Revocation

```typescript
async function revokeApiKey(
  keyId: string,
  reason: string,
  revokedBy: string
): Promise<void> {
  // 1. Get current key state
  const key = await apiKeyRepository.findById(keyId);
  if (!key) {
    throw new NotFoundError('API key not found');
  }

  // 2. Verify permissions
  if (!await this.canRevoke(key, revokedBy)) {
    throw new ForbiddenError('Cannot revoke this key');
  }

  // 3. Update database
  key.status = 'revoked';
  key.revokedAt = new Date();
  key.revokedBy = revokedBy;
  key.revocationReason = reason;
  await apiKeyRepository.save(key);

  // 4. Purge cache
  await redis.del(`api-key:${keyId}`);
  await redis.del(`api-key:${key.tenantId}:${keyId}`);

  // 5. Invalidate nonces
  await redis.keys(`nonce:${key.tenantId}:${keyId}:*`)
    .then(keys => keys.forEach(k => redis.del(k)));

  // 6. Log audit
  await this.auditLog.log({
    eventType: 'AUTH_KEY_REVOKED',
    tenantId: key.tenantId,
    details: { keyId, reason, revokedBy }
  });

  // 7. Notify
  await this.notificationService.notify(key.tenantId, {
    type: 'SECURITY_ALERT',
    message: 'API key has been revoked',
    details: { reason }
  });
}
```

---

## Automated Triggers

| Trigger | Action | Speed |
|---------|--------|-------|
| Anomaly score > 9 | Auto-revoke key | Immediate |
| Brute force detected | Lock account | Immediate |
| Credential in public leak | Alert + suggest revoke | 5 min |
| Provider breach notification | Revoke provider secrets | Immediate |

---

## Recovery Procedure

### For Tenants

```
1. Login to dashboard
2. Navigate to Security → API Keys
3. Click "Generate New Key"
4. Copy and store new key securely
5. Update applications with new key
6. Delete old revoked keys (if any)
```

### For Users

```
1. Request password reset
2. Verify identity via email
3. Set new password
4. Review recent activity
5. Revoke suspicious sessions
6. Enable MFA (if available)
```

---

## Failure Modes

| Mode | Impact | Mitigation |
|------|--------|------------|
| Redis down | Cache purge fails | Retry queue, manual cleanup |
| DB update fails | Inconsistent state | Transaction rollback |
| Notification fails | Tenant unaware | Secondary notification channel |
| Revocation not propagating | Delayed effect | Cache TTL (5 min max) |

---

## Trust Boundaries

| Action | Authorization |
|--------|---------------|
| Revoke own key | Key owner |
| Revoke tenant keys | Tenant admin |
| Revoke any key | Platform admin only |
| Global revocation | Security lead + CTO |

---

## Related Documents

- `05-security/api-key-security.md`
- `05-security/incident-response.md`
- `05-security/credential-lineage.md`
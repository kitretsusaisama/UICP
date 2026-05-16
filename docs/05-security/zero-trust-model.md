# Zero-Trust Security Model

## Metadata
```yaml
title: Zero-Trust Security Model
domain: security
criticality: CRITICAL
security-impact: CRITICAL
ai-ingestable: true
```

---

## Executive Summary

UICP implements zero-trust security: no implicit trust, every request validated, tenant isolation enforced at every layer.

---

## Core Principles

### 1. Never Trust, Always Verify
- All credentials validated on every request
- No rely on network location or VPN
- API keys, JWTs, sessions all verified

### 2. Least Privilege Access
- API keys scoped to specific permissions
- Roles define minimum necessary access
- Session tokens expire automatically

### 3. Assume Breach
- Monitor for anomalies continuously
- Immutable audit logs for forensics
- Emergency revocation capabilities

---

## Authentication Flow

```
Request → UnifiedAuthGuard
   ↓
Extract credential (Bearer token / X-API-Key / X-Session-Token)
   ↓
Detect auth method (JWT / API_KEY / SESSION / INTERNAL_SERVICE)
   ↓
Validate credential (signature / HMAC / token lookup)
   ↓
Extract tenantId from credential (NOT from header!)
   ↓
Set request context (tenantId, userId, permissions)
   ↓
Controller processes with tenant context
```

---

## Trust Boundaries

| Layer | Trust Level | Justification |
|-------|-------------|---------------|
| Internet | ❌ Untrusted | Any client, any IP |
| API Gateway | ✅ Trusted | Validates all credentials |
| Tenant Resolver | ✅ Trusted | Extracts tenant context |
| Application Svc | ✅ Trusted | Business logic |
| Repository | ✅ Trusted | Data access |
| MySQL | ⚠️ Conditional | Behind firewall |
| Redis | ⚠️ Conditional | Behind firewall |

---

## Security Controls

### Token Security

| Control | Implementation |
|---------|-----------------|
| Signature | RS256 for JWT, HMAC-SHA256 for API keys |
| Expiration | 15-min access, 7-day refresh |
| Rotation | Auto-rotate on refresh |
| Revocation | Redis key invalidation |

### Tenant Isolation

| Control | Implementation |
|---------|----------------|
| Data | Row-level filtering by tenant_id |
| Rate Limits | Per tenant, per API key |
| Auditing | Tenant-scoped logs |
| Quotas | Configurable per tenant |

### API Key Security

```
Format: {prefix}{ULID26}{HMAC44?}

Validation:
1. Check prefix (uF/pB/sF/tB)
2. Extract ULID, validate format
3. If secret key, verify HMAC signature
4. Look up key in repository
5. Check status (active/not expired)
6. Extract tenantId from key record
7. Apply rate limits
```

---

## Threat Model

### Attack Vectors

| Vector | Mitigation |
|--------|------------|
| Token Theft | Short lifespan, rotation |
| API Key Compromise | HMAC validation, emergency revocation |
| Session Hijacking | Redis validation, IP tracking |
| Brute Force | Rate limiting, account lockout |
| Credential Stuffing | Anomaly detection, MFA |

### Defenses

- **Rate Limiting**: Per API key, not per IP
- **MFA**: OTP for sensitive operations
- **Device Trust**: Fingerprint validation
- **Anomaly Detection**: Impossible travel, unusual hours

---

## Incident Response

### Emergency Revocation Flow

```
1. Security team identifies compromised key/token
2. Call emergency revocation endpoint
3. Redis cache immediately purged
4. MySQL key status set to revoked
5. All active sessions for tenant invalidated
6. Alert sent to security channel
7. User notified of compromise
```

### Rollback Procedure

1. Revoke via API: `POST /v1/tenant/api-keys/:id/revoke`
2. Purge sessions: `DEL session:{tenantId}:*`
3. Block IP: Add to firewall blocklist
4. Notify affected users

---

## Compliance

- **Audit Logs**: Immutable, 7-year retention
- **Data Encryption**: At rest (AES-256), in transit (TLS 1.3)
- **Access Logging**: All API calls logged
- **Consent Management**: GDPR-compliant consent tracking

---

## Related Documents

- `05-security/api-key-security.md`
- `05-security/replay-protection.md`
- `05-security/threat-model.md`
- `16-failure-models/replay-attacks.md`


# Authentication Security

## Metadata
```yaml
title: Authentication Security Controls
domain: security
owner: security-team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - replay-prevention.md
  - token-model.md
related-docs:
  - device-trust.md
  - suspicious-login-detection.md
  - auth-rate-limits.md
related-queues:
  - security-events
  - auth-analytics
  - audit-events
related-services:
  - SecurityService
  - AnomalyDetector
  - AuditService
related-runtime-states:
  - AUTH_SECURE
  - THREAT_DETECTED
  - ACCOUNT_COMPROMISED
```

---

## Cryptographic Controls

### Key Management

Asymmetric keys (RS256 for JWT) rotate annually with key IDs for identification. Keys store in KMS (AWS KMS, GCP Cloud KMS, or HashiCorp Vault). Private keys never expose outside the service.

### Token Signing

All JWTs sign with RS256 using 2048-bit RSA keys. Key rotation involves publishing new public key to JWKS endpoint while retaining old key for existing token validation during transition period.

### Password Hashing

Passwords hash using Argon2id with high security parameters:

```
Memory: 64 MB
Iterations: 3
Parallelism: 4
Salt: 16 bytes (unique per password)
```

---

## Threat Mitigation

### Brute Force Protection

Failed authentication attempts track per account. After 5 failures within 15 minutes, account locks for 30 minutes. Exponential backoff applies for repeated failures.

### Credential Stuffing Detection

Login attempts from IP addresses with high failure rates trigger additional verification. Known compromised credential databases (HaveIBeenPwned) check against submitted passwords.

### Session Hijacking Prevention

Sessions invalidate on password change. Device fingerprint binding prevents session token theft across devices. IP address anomalies trigger re-authentication.

### Token Theft Prevention

Access tokens have short 15-minute lifetime. Refresh tokens rotate on use and store in server-side Redis. API keys include timestamp in signature for replay prevention.

---

## Audit and Monitoring

### Authentication Events

All authentication events log to the audit service:

| Event | Data Captured | Retention |
|-------|---------------|------------|
| Login Success | User, IP, Device, Time | 2 years |
| Login Failed | User, IP, Device, Reason | 1 year |
| Token Issued | User, Token ID, Scope | 90 days |
| Session Created | Session ID, Device, IP | 2 years |
| MFA Enabled | User, Method, Time | 2 years |

### Security Alerts

Anomaly detection triggers alerts for suspicious patterns:

- Impossible travel (login from distant locations in short time)
- New device with known credentials
- Unusual access times
- Mass account access attempts

---

## Compliance Controls

### Data Protection

Authentication data encrypts at rest using AES-256-GCM. TLS 1.3 secures all network communication. Session tokens never expose in URLs or logs.

### Privacy

Passwords never log or expose. Token contents minimal to reduce exposure surface. PII handling follows GDPR and applicable regulations.

### Access Controls

Administrative access to authentication systems requires MFA. Audit logs immutable and independent of the authentication system.

---

## Security Configuration

| Control | Configuration | Status |
|---------|---------------|--------|
| Password Hashing | Argon2id, 64MB memory | Enabled |
| JWT Signing | RS256, 2048-bit | Enabled |
| Token Lifetime | Access: 15min, Refresh: 7d | Enabled |
| Session Timeout | 24 hours | Enabled |
| MFA | TOTP, SMS, Email | Available |
| Rate Limiting | Per-endpoint, per-user | Enabled |
| Account Lockout | 5 attempts, 30min | Enabled |
| Audit Logging | All auth events | Enabled |

---

## Related Documents

- `auth-overview.md` - Overview
- `replay-prevention.md` - Replay attack prevention
- `auth-rate-limits.md` - Rate limiting
- `suspicious-login-detection.md` - Anomaly detection
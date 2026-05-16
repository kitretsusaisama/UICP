# OTP Flow

## Metadata
```yaml
title: One-Time Password (OTP) Flow
domain: authentication
owner: identity-team
criticality: CRITICAL
runtime-impact: MEDIUM
security-impact: CRITICAL
queue-impact: LOW
provider-impact: MEDIUM
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - login-flow.md
  - auth-security.md
related-docs:
  - email-verification-flow.md
  - device-trust.md
  - auth-edge-cases.md
related-queues:
  - otp-events
  - security-alerts
related-services:
  - OtpService
  - EmailProvider
  - SmsProvider
  - RedisCacheAdapter
related-runtime-states:
  - OTP_SENT
  - OTP_VALIDATED
  - OTP_EXPIRED
  - OTP_FAILED
```

---

## OTP Generation

### Code Generation

The system generates cryptographically random 6-digit codes using secure random number generator. Each code has a 5-minute validity window. Codes are stored in Redis with TTL matching validity period.

```typescript
interface OtpConfig {
  digits: 6;
  ttl: 300; // seconds
  maxAttempts: 3;
  algorithm: 'totp' | 'hotp';
}
```

### Delivery Channels

OTP delivery supports multiple channels based on user preference and account configuration:

- **Email**: Default for verification, MFA
- **SMS**: Secondary for MFA when phone verified
- **Authenticator App**: TOTP for highest security (no delivery dependency)

### Rate Limiting

OTP send requests limit to 3 requests per minute per user. Excessive requests return `RATE_LIMIT_EXCEEDED` error. This prevents OTP flooding attacks.

---

## OTP Verification

### Validation Process

Client submits OTP via `POST /v1/auth/attempt` with `authMethod: "otp"`. The validation retrieves the stored code, performs constant-time comparison, and marks the code as used (single-use enforcement).

```typescript
async function validateOtp(userId: string, code: string): Promise<boolean> {
  const stored = await this.redis.get(`otp:${userId}`);

  if (!stored) {
    throw new OtpExpiredError();
  }

  if (stored.used) {
    throw new OtpAlreadyUsedError();
  }

  // Constant-time comparison
  const valid = await this.constantTimeEqual(stored.code, code);

  if (!valid) {
    await this.redis.incr(`otp-attempts:${userId}`);
    throw new OtpInvalidError();
  }

  // Mark as used
  await this.redis.set(`otp:${userId}:used`, '1', { ttl: 300 });

  return true;
}
```

### Attempt Tracking

After 3 failed OTP attempts, the code expires and user must request new OTP. This prevents brute-force attacks on valid codes.

---

## TOTP (Time-Based OTP)

### Authenticator App Setup

Users enable TOTP through security settings. The system generates a secret key displayed as QR code (QRNG-encoded) and backup codes for recovery. The secret stores encrypted in the user record.

```json
{
  "totp": {
    "enabled": true,
    "algorithm": "SHA1",
    "digits": 6,
    "period": 30,
    "backupCodesRemaining": 10
  }
}
```

### TOTP Validation

TOTP validation uses the RFC 6238 algorithm with 30-second time window and ±1 window tolerance (90 seconds total). This accommodates clock drift between server and client devices.

---

## OTP Security Controls

### Channel Security

| Channel | Encryption | Delivery Security |
|---------|------------|-------------------|
| Email | TLS 1.3 | SPF/DKIM/DMARC |
| SMS | At rest | Carrier-grade security |
| TOTP | AES-256 | App-based, offline |

### Fraud Prevention

OTP sending triggers monitoring for suspicious patterns: bulk sending, unusual destinations, and delivery failures. Anomaly detection feeds security alerts queue.

---

## Related Documents

- `email-verification-flow.md` - Email verification with OTP
- `auth-security.md` - Security controls overview
- `auth-edge-cases.md` - Edge case handling
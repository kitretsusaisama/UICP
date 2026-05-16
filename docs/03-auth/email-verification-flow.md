# Email Verification Flow

## Metadata
```yaml
title: Email Verification Flow
domain: authentication
owner: identity-team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - signup-flow.md
  - otp-flow.md
related-docs:
  - password-reset-flow.md
  - login-flow.md
  - auth-security.md
related-queues:
  - verification-events
  - email-sent
related-services:
  - EmailVerificationService
  - EmailProvider
  - UserRepository
related-runtime-states:
  - VERIFICATION_PENDING
  - VERIFICATION_SENT
  - VERIFICATION_COMPLETED
  - VERIFICATION_FAILED
```

---

## Verification Process

### Trigger Points

Email verification initiates in these scenarios:

- New user signup
- Email address change
- Account recovery
- Admin-initiated verification

### Verification Code Generation

The system generates a 6-digit numeric code with 24-hour validity. Codes store in Redis with TTL matching validity period. Each code has maximum 3 validation attempts.

```typescript
interface VerificationCode {
  userId: string;
  code: string;
  purpose: 'signup' | 'email_change' | 'recovery';
  expiresAt: Date;
  maxAttempts: number;
}
```

### Email Delivery

Verification email sends via configured email provider. The email contains the verification code and a backup verification link. HTML and plain-text versions available.

```
Email Template Variables:
- {{userName}}
- {{verificationCode}}
- {{verificationLink}}
- {{expiryHours}}
- {{supportUrl}}
```

### Verification Confirmation

User submits code via `POST /v1/auth/verify/email` with code. On success, the user's email status updates to `VERIFIED` and account becomes fully active.

---

## Email Change Verification

### New Email Verification

When user requests email address change, the new email receives verification code. The old email receives notification of the change request. Both emails must verify for change to complete.

```
Email Change Flow:
1. User requests email change to new@example.com
2. Verification sent to new@example.com
3. Confirmation sent to old@example.com
4. Both must verify within 24 hours
5. Email updates on both verification
```

### Pending Status

During email change, both old and new emails remain associated with account. Verification status tracks separately for each.

---

## Security Controls

### Rate Limiting

Verification code requests limit to 5 per hour per user. Failed verification attempts reset at 3. Excessive failures trigger CAPTCHA.

### Reuse Prevention

Verification codes are one-time use. After successful verification or expiry, codes delete from storage. Reuse attempts fail.

### Email Hijacking Prevention

If account has no verified email, password reset requires additional verification (MFA or backup code). This prevents account takeover through email-only reset.

---

## Related Documents

- `signup-flow.md` - Signup verification
- `password-reset-flow.md` - Reset verification
- `auth-security.md` - Security controls
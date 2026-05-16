# Password Reset Flow

## Metadata
```yaml
title: Password Reset Flow
domain: authentication
owner: identity-team
criticality: CRITICAL
runtime-impact: MEDIUM
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - login-flow.md
  - otp-flow.md
related-docs:
  - signup-flow.md
  - email-verification-flow.md
  - session-management.md
related-queues:
  - password-reset-events
  - security-alerts
related-services:
  - PasswordResetService
  - EmailProvider
  - UserRepository
  - SessionService
related-runtime-states:
  - RESET_REQUESTED
  - RESET_INITIATED
  - RESET_COMPLETED
  - RESET_FAILED
```

---

## Password Reset Process

### Step 1: Reset Request

User initiates password reset via `POST /v1/auth/password/reset/request` with email address. The system validates email exists and account is active. No indication of account existence returned to prevent enumeration.

```json
{
  "email": "user@example.com"
}
```

### Step 2: Reset Token Generation

On valid request, the system generates a cryptographically secure reset token (256-bit random). The token stores in Redis with 1-hour TTL. A password reset email sends to the user's verified email address.

```typescript
interface ResetToken {
  userId: string;
  token: string;
  issuedAt: Date;
  expiresAt: Date; // 1 hour from issue
  ipAddress: string; // For audit
}
```

### Step 3: Token Validation

User clicks reset link containing token. The `POST /v1/auth/password/reset/confirm` endpoint validates token hasn't expired, hasn't been used, and matches user. Rate limiting applies (3 attempts per token).

### Step 4: Password Update

On valid token, user submits new password meeting complexity requirements. The password updates in the credential store, triggering session invalidation across all devices.

```typescript
async function resetPassword(userId: string, newPassword: string): Promise<void> {
  // Validate password requirements
  await this.validatePasswordStrength(newPassword);

  // Hash and store
  const hash = await this.hashPassword(newPassword);
  await this.credentialStore.update(userId, { passwordHash: hash });

  // Invalidate all sessions
  await this.sessionService.invalidateAllUserSessions(userId);

  // Send notification
  await this.notifyUser(userId, 'password_changed');
}
```

---

## Security Controls

### Token Entropy

Reset tokens use 256-bit cryptographic randomness, making brute-force infeasible. Tokens cannot be derived from user ID or timestamp.

### One-Time Use

Reset tokens mark as used immediately upon successful password change. Reuse attempts fail with `TOKEN_ALREADY_USED` error.

### Account Lockout Prevention

Password reset does not contribute to account lockout counters. However, repeated reset requests trigger rate limiting (5 requests per hour per email).

### Suspicious Activity Detection

Reset requests from new IP addresses or unusual patterns trigger security alerts. Users receive notification of reset request regardless of outcome.

---

## Password Requirements

Same requirements as initial signup:

- Minimum 12 characters
- Uppercase and lowercase letters
- At least one digit
- At least one special character
- Not in breach database

---

## Related Documents

- `signup-flow.md` - Initial password requirements
- `session-management.md` - Session invalidation
- `auth-security.md` - Security controls
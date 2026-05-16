# Signup Flow

## Metadata
```yaml
title: User Signup Flow
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
  - email-verification-flow.md
  - otp-flow.md
related-docs:
  - login-flow.md
  - password-reset-flow.md
  - org-model.md
related-queues:
  - user-created
  - verification-sent
  - welcome-events
related-services:
  - UnifiedAuthService
  - UserRepository
  - EmailProvider
  - QueueService
related-runtime-states:
  - USER_CREATED
  - VERIFICATION_PENDING
  - ACCOUNT_ACTIVATED
```

---

## Signup Process

### Step 1: Identity Collection

The client submits registration request to `POST /v1/auth/signup` with required identity data. The payload includes email, password (meeting complexity requirements), and optional profile information. The system performs initial validation before any storage operations.

```json
{
  "email": "user@example.com",
  "password": "SecureP@ss123",
  "profile": {
    "firstName": "John",
    "lastName": "Doe"
  },
  "tenantId": "tenant-uuid"
}
```

### Step 2: Credential Processing

Passwords undergo Argon2id hashing with configurable memory cost (64MB default), parallelism (4), and iterations (3). The hash is never stored in plain text. Duplicate email detection prevents account takeover through registration.

### Step 3: Account Creation

The `CreateUserCommand` handler creates the user entity with `VERIFICATION_PENDING` status. A unique user ID (ULID) assigns to the account. The tenant association establishes during creation, enforcing tenant isolation from the first moment.

### Step 4: Verification Trigger

Immediately after account creation, the verification flow initiates. The system generates a verification code valid for 24 hours. Email delivery occurs through the configured email provider (SendGrid, SES, or custom SMTP).

```
Verification Flow:
1. Generate 6-digit code
2. Store in Redis: key = verify:{userId}, value = code, TTL = 86400
3. Send email via EmailProvider
4. Queue welcome event for async processing
```

---

## Signup Security Controls

### Rate Limiting

Signup endpoints enforce rate limits to prevent mass account creation: 5 requests per IP per hour, 10 requests per email per day. Exceeded limits trigger CAPTCHA challenge or temporary block.

### Email Validation

The system validates email format syntactically and performs DNS MX record verification for domain existence. Disposable email domains block through configurable blocklist.

### Password Requirements

Minimum 12 characters, requires uppercase, lowercase, digit, and special character. Common password check against breach database (HaveIBeenPwned API) flags compromised passwords.

---

## Post-Signup Behavior

### Auto-Login After Verification

Upon email verification, the system automatically creates a session and returns access tokens. Users can immediately access the platform without additional login step.

### Welcome Queue Event

The `welcome-events` queue receives a message for post-signup processing: profile setup prompts, feature tour triggers, and onboarding workflow initiation.

---

## Related Documents

- `login-flow.md` - Authentication after signup
- `email-verification-flow.md` - Verification details
- `org-model.md` - Tenant and organization structure
# Login Flow

## Metadata
```yaml
title: User Login Flow
domain: authentication
owner: identity-team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: LOW
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - session-management.md
  - otp-flow.md
related-docs:
  - signup-flow.md
  - password-reset-flow.md
  - suspicious-login-detection.md
related-queues:
  - auth-attempts
  - security-alerts
  - session-events
related-services:
  - UnifiedAuthService
  - CredentialRepository
  - SessionService
  - AnomalyDetector
related-runtime-states:
  - LOGIN_SUCCESS
  - LOGIN_FAILED
  - MFA_REQUIRED
  - ACCOUNT_LOCKED
```

---

## Login Process

### Step 1: Credential Submission

Client authenticates via `POST /v1/auth/attempt` with identity and authentication method. The unified auth endpoint handles all methods through a consistent interface.

```json
{
  "identity": "user@example.com",
  "authMethod": "password",
  "secret": "UserPassword123",
  "deviceFingerprint": "abc123def456"
}
```

### Step 2: Credential Validation

The `UnifiedAuthService.attempt()` method retrieves stored credentials for the identity. For password method, Argon2id verification compares submitted password against stored hash. Multiple failures trigger account lockout.

### Step 3: Risk Assessment

Before issuing tokens, the anomaly detector evaluates the login attempt against historical patterns. Risk signals include new device, unusual location, impossible travel, and time-of-day anomalies.

```typescript
interface RiskAssessment {
  score: number; // 0-100
  signals: RiskSignal[];
  requiresMfa: boolean;
  blockLogin: boolean;
}
```

### Step 4: Token Issuance

On successful authentication with acceptable risk, the system issues token pair: JWT access token (15-minute expiry) and refresh token (7-day expiry). A session is created in Redis with device binding.

### Step 5: MFA Challenge

For accounts with MFA enabled or risk-triggered step-up, the flow redirects to OTP verification. The login attempt returns `MFA_REQUIRED` status, prompting OTP submission before token issuance.

---

## Login Response

```json
{
  "status": "success",
  "principal": {
    "userId": "ulid-abc123",
    "email": "user@example.com",
    "tenantId": "ulid-tenant"
  },
  "membership": {
    "orgId": "org-uuid",
    "roles": ["member"]
  },
  "actor": {
    "actorId": "ulid-actor",
    "permissions": ["read", "write"]
  },
  "tokens": {
    "accessToken": "eyJ...",
    "refreshToken": "eyJ..."
  }
}
```

---

## Failed Login Handling

### Account Lockout

After 5 failed attempts within 15 minutes, the account locks for 30 minutes. Lockout duration increases exponentially with repeated failures. Administrative unlock available through security console.

### Credential Leak Detection

Failed login with correct password (detected through timing analysis) triggers credential leak warning. Users receive notification to change password proactively.

---

## Related Documents

- `signup-flow.md` - Registration process
- `otp-flow.md` - MFA implementation
- `suspicious-login-detection.md` - Anomaly detection
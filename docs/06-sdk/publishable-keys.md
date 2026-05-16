# Publishable Keys

## Metadata
```yaml
title: Publishable Keys
domain: sdk/security
owner: security-team
criticality: HIGH
runtime-impact: NONE
security-impact: HIGH
queue-impact: NONE
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - initialization.md
related-docs:
  - 03-auth/auth-overview.md
  - 05-security/zero-trust-model.md
related-queues: []
related-services:
  - auth-service
```

---

## Overview

Publishable keys are a fundamental security feature in UICP's key-based authentication system. They enable client-side integration while maintaining strict security boundaries. Unlike secret keys which provide full API access, publishable keys are deliberately restricted to prevent misuse even if exposed.

## Key Format

Publishable keys follow a specific format that encodes environment and tenant information:

- Live environment: `uF` prefix (e.g., `uF1abc123def456ghi789`)
- Development/Sandbox: `pB` prefix (e.g., `pB1abc123def456ghi789`)

The prefix indicates the environment, followed by a unique identifier and tenant information.

## Security Properties

### Embeddable in Client Code

Publishable keys are designed to be safely included in frontend applications, mobile apps, and edge functions. They can appear in source code, configuration files, and environment variables without compromising system security.

### Restricted Capabilities

A publishable key cannot perform the following operations:

- Create, modify, or delete users
- Access administrative functions
- Modify tenant configuration
- Access sensitive audit logs
- Enqueue to privileged queues
- Perform cross-tenant operations

### Automatic Tenant Isolation

Each publishable key is bound to a specific tenant. Even if a key is misused, it can only access resources within its assigned tenant scope.

## Use Cases

Publishable keys are ideal for:

- Frontend web applications
- Mobile applications (iOS, Android, React Native)
- Edge functions and serverless
- IoT devices with limited trust model
- Public API integrations

```typescript
// Correct usage: Client-side SDK
const client = new UICPClient({
  publishableKey: 'uF1abc123def456ghi789'
});

// Incorrect: Never use secret keys in frontend code
// secretKey: 'sF1abc...' should NEVER be in frontend
```

## Key Management

### Rotation Strategy

Publishable keys should be rotated periodically, especially when team members with access leave. The SDK supports smooth key rotation without service interruption.

```typescript
const client = new UICPClient({
  publishableKey: 'uF1newkey...',
  fallbackKey: 'uFoldkey...' // Optional fallback during rotation
});
```

### Revocation

Compromised keys can be immediately revoked through the administrative API. All active sessions using the revoked key are terminated.

## Best Practices

1. Use environment-specific keys (pB for dev, uF for production)
2. Rotate keys at least quarterly
3. Revoke keys immediately upon suspected compromise
4. Use separate keys for different applications
5. Monitor key usage for anomaly detection

---

## Related Documents

- `03-auth/auth-overview.md` - Authentication concepts
- `05-security/zero-trust-model.md` - Security principles
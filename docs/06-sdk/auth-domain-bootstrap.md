# Authentication Domain Bootstrap

## Metadata
```yaml
title: Auth Domain Bootstrap
domain: sdk/auth
owner: platform-team
criticality: HIGH
runtime-impact: LOW
security-impact: HIGH
queue-impact: NONE
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - initialization.md
  - session-usage.md
related-docs:
  - 03-auth/auth-overview.md
  - 03-auth/login-flow.md
related-queues: []
related-services:
  - auth-service
  - identity-service
```

---

## Overview

Authentication domain bootstrap is the process of initializing the SDK's authentication context for a user session. This involves establishing the initial authentication state, retrieving session tokens, and setting up the communication channels required for authenticated API access.

## Bootstrap Flow

### Step 1: Key Verification

Before any authentication attempt, the SDK validates the provided key format and performs a preliminary connectivity check.

```typescript
const client = new UICPClient({ publishableKey: 'uF1...' });

// Bootstrap authentication context
await client.bootstrap();
```

### Step 2: Domain Resolution

The SDK resolves the authentication domain based on the tenant configuration. This determines the auth endpoints, token service location, and session management rules.

```typescript
// Domain resolution happens automatically during bootstrap
const domainInfo = await client.auth.getAuthDomain();
console.log(domainInfo.tokenEndpoint); // https://auth.uicp.io/oauth/token
```

### Step 3: Session Initialization

The final step establishes the session state with an anonymous or pre-authenticated context. For authenticated users, the session is populated with user information and permissions.

## Programmatic Bootstrap

Applications can perform programmatic bootstrap to restore sessions or implement custom authentication flows:

```typescript
async function restoreSession(refreshToken: string) {
  const client = new UICPClient({ publishableKey: 'uF1...' });

  // Use refresh token to restore session
  const session = await client.auth.refresh(refreshToken);

  // Bootstrap with restored session
  await client.bootstrap(session);

  return client;
}
```

## Domain Configuration

Authentication domains can be customized for enterprise tenants requiring specific identity providers or authentication policies:

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  authDomain: {
    issuer: 'https://auth.enterprise.com',
    provider: 'saml',
    mfaRequired: true
  }
});
```

## Error Handling

Bootstrap failures can occur due to network issues, invalid keys, or domain configuration problems. The SDK provides detailed error information for debugging:

```typescript
try {
  await client.bootstrap();
} catch (error) {
  if (error.code === 'INVALID_KEY') {
    // Key format or validity issue
  } else if (error.code === 'DOMAIN_UNREACHABLE') {
    // Auth domain not accessible
  }
}
```

## Session Persistence

After successful bootstrap, the session can be persisted for restoration on subsequent application loads. The SDK supports various persistence mechanisms depending on platform capabilities.

---

## Related Documents

- `03-auth/login-flow.md` - Login flow details
- `session-usage.md` - Session management
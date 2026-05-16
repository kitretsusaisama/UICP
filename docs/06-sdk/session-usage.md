# Session Usage

## Metadata
```yaml
title: Session Usage
domain: sdk/sessions
owner: platform-team
criticality: HIGH
runtime-impact: LOW
security-impact: HIGH
queue-impact: NONE
provider-impact: NONE
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - token-handling.md
  - auth-domain-bootstrap.md
related-docs:
  - 03-auth/session-management.md
  - 02-runtime/session-runtime.md
related-queues: []
related-services:
  - session-service
  - token-service
```

---

## Overview

Session management is a core responsibility of the UICP SDK. Sessions encapsulate user authentication state, access tokens, refresh credentials, and metadata required for maintaining authenticated communication with services.

## Session Lifecycle

### Creation

Sessions are created upon successful authentication. The SDK handles token acquisition automatically:

```typescript
const client = new UICPClient({ publishableKey: 'uF1...' });

const session = await client.auth.attempt({
  identity: 'user@example.com',
  authMethod: 'password',
  secret: 'password'
});

console.log(session.accessToken); // JWT access token
console.log(session.refreshToken); // Long-lived refresh credential
console.log(session.expiresIn); // Token lifetime in seconds
```

### Active State

During an active session, the SDK automatically handles token refresh before expiration. Applications can access current session state:

```typescript
const currentSession = client.session;
console.log(currentSession.userId);
console.log(currentSession.scopes);
console.log(currentSession.expiresAt);
```

### Termination

Sessions can be terminated through logout, expiration, or revocation. The SDK provides comprehensive termination handling:

```typescript
// Graceful logout - revokes tokens
await client.auth.logout();

// Force termination - immediate session destruction
await client.auth.logout({ revokeAll: true });
```

## Session Storage

### Browser Environments

In browser contexts, sessions are stored using HttpOnly cookies when possible, providing protection against XSS attacks. Fallback mechanisms use encrypted local storage.

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  sessionStorage: 'cookie' // or 'localStorage'
});
```

### Server-Side Sessions

Backend SDKs store sessions in memory by default, with options for Redis or database persistence in distributed environments.

## Session Validation

The SDK performs automatic session validation on each request. Invalid sessions trigger automatic re-authentication or error propagation:

```typescript
try {
  await client.users.me();
} catch (error) {
  if (error.code === 'SESSION_EXPIRED') {
    // Attempt refresh or prompt re-login
  }
}
```

## Multi-Session Support

Applications can manage multiple concurrent sessions, useful for supporting multiple user contexts:

```typescript
const user1Session = client.session;
const user2Client = new UICPClient({ publishableKey: 'uF1...' });
await user2Client.auth.attempt({ /* credentials */ });
```

## Security Considerations

Session tokens are sensitive credentials requiring protection. The SDK implements token encryption, automatic rotation, and secure storage appropriate for each platform.

---

## Related Documents

- `03-auth/session-management.md` - Full session management guide
- `token-handling.md` - Token lifecycle details
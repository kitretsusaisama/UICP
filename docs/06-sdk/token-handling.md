# Token Handling

## Metadata
```yaml
title: Token Handling
domain: sdk/tokens
owner: security-team
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
  - publishable-keys.md
  - session-usage.md
related-docs:
  - 03-auth/token-model.md
  - 03-auth/refresh-rotation.md
related-queues: []
related-services:
  - token-service
  - auth-service
```

---

## Overview

Token handling encompasses the complete lifecycle of authentication tokens including acquisition, storage, refresh, rotation, and invalidation. Proper token management is critical for security and user experience.

## Token Types

### Access Tokens

Short-lived tokens (typically 15-60 minutes) used for API authentication. The SDK automatically handles access token injection and expiration:

```typescript
// Access token is automatically included in requests
const user = await client.users.me();

// Check token validity
console.log(client.tokenManager.accessTokenExpiry);
```

### Refresh Tokens

Long-lived tokens (days to months) used to obtain new access tokens without re-authentication:

```typescript
const session = await client.auth.attempt({
  identity: 'user@example.com',
  authMethod: 'password',
  secret: 'password'
});

// Store refresh token securely
await secureStorage.set('refreshToken', session.refreshToken);
```

### ID Tokens

JWT tokens containing user identity claims, useful for federated authentication scenarios.

## Automatic Token Refresh

The SDK automatically refreshes expired access tokens using refresh tokens:

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  autoRefresh: true,        // Default: true
  refreshBuffer: 60         // Refresh 60 seconds before expiry
});

// When access token expires, SDK automatically refreshes
const data = await client.users.list(); // May trigger refresh
```

## Manual Token Operations

For custom flows, token operations can be invoked manually:

```typescript
// Manual refresh
const newTokens = await client.auth.refresh(currentRefreshToken);

// Revoke tokens
await client.auth.revoke(accessToken);
await client.auth.revokeRefreshToken(refreshToken);

// Validate token without using it
const validation = await client.tokens.validate(accessToken);
```

## Token Storage

### Browser Storage

The SDK supports multiple storage mechanisms in browser environments:

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  tokenStorage: {
    // HttpOnly cookies - most secure, requires server support
    type: 'cookie',

    // Or encrypted localStorage for wider compatibility
    type: 'localStorage',
    encryptionKey: process.env.UICP_STORAGE_KEY
  }
});
```

### Server-Side Storage

Backend SDKs typically store tokens in memory or external storage:

```typescript
const client = new UICPBackendClient({
  secretKey: 'sF1...',
  tokenStorage: {
    type: 'redis',
    redis: redisClient
  }
});
```

## Token Lifecycle Events

The SDK emits events for token lifecycle changes:

```typescript
client.on('tokenRefreshed', (newAccessToken) => {
  console.log('Token refreshed:', newAccessToken.sub);
});

client.on('tokenExpired', () => {
  console.log('Access token expired');
});

client.on('tokensRevoked', () => {
  console.log('All tokens revoked');
});
```

## Security Best Practices

Never expose tokens in URLs, logs, or error messages. Use secure storage mechanisms. Implement token rotation policies. Monitor for anomalous token usage.

---

## Related Documents

- `03-auth/token-model.md` - Token architecture
- `03-auth/refresh-rotation.md` - Refresh token rotation
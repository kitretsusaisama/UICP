# Error Handling

## Metadata
```yaml
title: Error Handling
domain: sdk/errors
owner: platform-team
criticality: HIGH
runtime-impact: LOW
security-impact: MEDIUM
queue-impact: NONE
provider-impact: NONE
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - api-client.md
  - retry-behavior.md
related-docs:
  - 03-auth/auth-overview.md
  - 02-runtime/fallback-runtime.md
related-queues: []
related-services: []
```

---

## Overview

The SDK provides a comprehensive error handling system with typed errors, automatic recovery mechanisms, and structured error information for debugging and user feedback.

## Error Types

### UICPErrors Base Class

All SDK errors extend from a common base class:

```typescript
import { UICPError, ValidationError, AuthError, NetworkError } from '@uicp/client';

try {
  await client.users.create({ name: '' }); // Missing required field
} catch (error) {
  if (error instanceof ValidationError) {
    console.log(error.fields); // { name: 'required' }
    console.log(error.code);   // 'VALIDATION_ERROR'
  }
}
```

### Error Categories

| Error Type | HTTP Status | Description |
|------------|-------------|-------------|
| ValidationError | 400 | Request validation failed |
| AuthError | 401/403 | Authentication/authorization failed |
| NetworkError | - | Network connectivity issues |
| RateLimitError | 429 | Rate limit exceeded |
| ServerError | 5xx | Internal server errors |
| NotFoundError | 404 | Resource not found |

## Error Properties

All errors include detailed information:

```typescript
try {
  await client.users.get('invalid_id');
} catch (error) {
  console.log(error.code);       // 'NOT_FOUND'
  console.log(error.message);    // 'User not found'
  console.log(error.status);     // 404
  console.log(error.requestId);  // 'req_abc123'
  console.log(error.details);   // { userId: 'invalid_id' }
}
```

## Handling Strategies

### Basic Error Handling

```typescript
try {
  const user = await client.users.get(userId);
} catch (error) {
  if (error instanceof NotFoundError) {
    // Handle missing user
    return null;
  } else if (error instanceof AuthError) {
    // Redirect to login
    router.push('/login');
  } else {
    // Show generic error
    showNotification('An unexpected error occurred');
    throw error; // Re-throw for debugging
  }
}
```

### Error Recovery

The SDK supports automatic error recovery for transient failures:

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  // Automatic recovery options
  retryOnError: true,
  fallbackOnAuthError: async () => {
    // Custom fallback: attempt token refresh
    await client.auth.refresh(refreshToken);
  }
});
```

### Global Error Handler

Set up a global error handler for consistent handling:

```typescript
client.on('error', (error) => {
  if (error instanceof AuthError) {
    analytics.track('auth_error', { code: error.code });
    router.push('/login');
  } else if (error instanceof NetworkError) {
    ui.showOfflineIndicator();
  } else {
    logger.error('Unhandled error', error);
  }
});
```

## Validation Errors

Validation errors provide detailed field-level information:

```typescript
try {
  await client.users.create({
    email: 'invalid-email',
    age: -5
  });
} catch (error) {
  if (error instanceof ValidationError) {
    // { email: 'invalid_email_format', age: 'must_be_positive' }
    console.log(error.fields);
    console.log(error.errors); // Array of detailed errors
  }
}
```

## Logging and Debugging

Enable detailed error logging for debugging:

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  debug: true,  // Enable debug logging
  logger: {
    error: (msg, error) => console.error(msg, error),
    warn: (msg) => console.warn(msg),
    info: (msg) => console.info(msg)
  }
});
```

---

## Related Documents

- `retry-behavior.md` - Retry on transient errors
- `observability-hooks.md` - Error observability
# Retry Behavior

## Metadata
```yaml
title: Retry Behavior
domain: sdk/retry
owner: platform-team
criticality: MEDIUM
runtime-impact: MEDIUM
security-impact: NONE
queue-impact: LOW
provider-impact: NONE
tenant-impact: LOW
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - api-client.md
  - error-handling.md
related-docs:
  - 02-runtime/retry-runtime.md
  - middleware.md
related-queues: []
related-services:
  - api-gateway
```

---

## Overview

The SDK implements automatic retry logic for failed requests, improving reliability and handling transient failures gracefully. Retry behavior is configurable to match application requirements and network conditions.

## Default Retry Policy

The SDK retries failed requests automatically with sensible defaults:

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  retries: 3,                    // Number of retry attempts
  retryDelay: 1000,              // Base delay in ms
  retryBackoff: 'exponential'    // or 'linear'
});
```

## Retryable Errors

The SDK automatically retries on transient failures:

- Network timeouts
- 503 Service Unavailable
- 429 Rate Limit (with retry-after header)
- 5xx Server errors

Non-retryable errors fail immediately:

- 400 Bad Request
- 401 Unauthorized
- 403 Forbidden
- 404 Not Found
- Validation errors

## Exponential Backoff

By default, retry delays follow exponential backoff:

```typescript
// With exponential backoff (default)
// Request 1: 1000ms delay
// Request 2: 2000ms delay
// Request 3: 4000ms delay

const client = new UICPClient({
  retries: 3,
  retryBackoff: 'exponential',
  retryDelay: 500  // Base delay
});
```

## Linear Backoff

For more predictable timing, linear backoff is available:

```typescript
// Linear backoff
// Request 1: 500ms delay
// Request 2: 1000ms delay
// Request 3: 1500ms delay

const client = new UICPClient({
  retries: 3,
  retryBackoff: 'linear',
  retryDelay: 500
});
```

## Jitter

Random jitter prevents thundering herd problems in distributed systems:

```typescript
const client = new UICPClient({
  retries: 3,
  jitter: 'full',   // 'full' adds randomness to full delay
                    // 'partial' adds small random component
                    // 'none' disables jitter
  maxJitter: 1000   // Maximum jitter in ms
});
```

## Custom Retry Logic

For complex retry requirements, implement custom retry handlers:

```typescript
const client = new UICPClient({
  shouldRetry: async (error, attempt) => {
    // Retry on network errors
    if (error.code === 'NETWORK_ERROR') return true;

    // Don't retry if max retries reached
    if (attempt >= 3) return false;

    // Custom logic: retry specific errors
    if (error.message?.includes('maintenance')) return true;

    return false;
  },
  onRetry: async (error, attempt) => {
    console.log(`Retrying after error: ${error.message}, attempt ${attempt}`);
    metrics.increment('retry.attempt');
  }
});
```

## Per-Request Override

Retry behavior can be customized per-request:

```typescript
await client.users.list({
  retries: 5,          // Override default
  timeout: 60000       // Extended timeout for this request
});
```

## Retry Events

Monitor retry activity through events:

```typescript
client.on('retry', (attempt, error) => {
  console.log(`Retry attempt ${attempt}: ${error.message}`);
});

client.on('retryExhausted', (error) => {
  console.error('All retries exhausted:', error);
});
```

---

## Related Documents

- `02-runtime/retry-runtime.md` - Server-side retry configuration
- `error-handling.md` - Error handling patterns
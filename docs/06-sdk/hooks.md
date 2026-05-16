# SDK Hooks

## Metadata
```yaml
title: SDK Hooks
domain: sdk/hooks
owner: platform-team
criticality: MEDIUM
runtime-impact: LOW
security-impact: NONE
queue-impact: NONE
provider-impact: NONE
tenant-impact: LOW
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - initialization.md
related-docs:
  - observability-hooks.md
  - middleware.md
related-queues: []
related-services: []
```

---

## Overview

SDK hooks provide extension points for injecting custom logic at specific points in the request lifecycle. Hooks enable cross-cutting concerns like logging, metrics, caching, and custom error handling without modifying core SDK code.

## Available Hooks

### Authentication Hooks

Hooks triggered during authentication operations:

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  hooks: {
    beforeAuth: async (attempt) => {
      console.log('Authentication attempt:', attempt.identity);
      return attempt;
    },
    afterAuth: async (result) => {
      metrics.increment('auth.success');
      return result;
    },
    onAuthFailure: async (error) => {
      alertSecurityTeam(error);
      throw error;
    }
  }
});
```

### Request Hooks

Hooks triggered during API requests:

```typescript
const client = new UICPClient({
  hooks: {
    beforeRequest: async (request) => {
      request.headers.set('X-Request-Id', generateId());
      return request;
    },
    afterResponse: async (response) => {
      metrics.trackLatency(response.duration);
      return response;
    },
    onRequestError: async (error) => {
      logger.error('Request failed', error);
      throw error;
    }
  }
});
```

### Session Hooks

Session lifecycle hooks:

```typescript
const client = new UICPClient({
  hooks: {
    onSessionCreated: async (session) => {
      analytics.track('session_created', { userId: session.userId });
    },
    onSessionRefreshed: async (session) => {
      // Session token was refreshed
    },
    onSessionExpired: async () => {
      ui.showNotification('Session expired, please re-login');
    }
  }
});
```

## Hook Configuration

Hooks can be configured globally or per-request:

```typescript
// Global hooks apply to all operations
client.hooks.beforeRequest = async (req) => req;

// Per-request hooks only apply to specific calls
await client.users.list({ hooks: { beforeRequest: customHook }});
```

## Performance Considerations

Hooks add overhead to request processing. Keep hook logic minimal and avoid synchronous operations in the critical path. Use async handlers and consider batching for metrics and logging.

## Error Handling in Hooks

Hook errors can interrupt the SDK workflow. Handle errors gracefully and decide whether to allow processing to continue or abort:

```typescript
const client = new UICPClient({
  hooks: {
    onError: async (error, context) => {
      if (error.code === 'NETWORK_ERROR') {
        // Allow retry to proceed
        return { allowContinue: true };
      }
      // Abort processing
      return { allowContinue: false };
    }
  }
});
```

---

## Related Documents

- `observability-hooks.md` - Observability-specific hooks
- `middleware.md` - Middleware pattern for extensibility
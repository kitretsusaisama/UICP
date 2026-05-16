# SDK Middleware

## Metadata
```yaml
title: SDK Middleware
domain: sdk/middleware
owner: platform-team
criticality: MEDIUM
runtime-impact: LOW
security-impact: LOW
queue-impact: NONE
provider-impact: NONE
tenant-impact: LOW
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - hooks.md
  - api-client.md
related-docs:
  - examples/nestjs.md
  - examples/express.md
related-queues: []
related-services: []
```

---

## Overview

Middleware provides a reusable, composable pattern for extending SDK functionality. Unlike hooks which are point-in-time callbacks, middleware wraps the entire request-response lifecycle, enabling complex processing pipelines.

## Middleware Pattern

Middleware functions intercept requests before they are sent and responses after they are received. They can modify requests, responses, or terminate the pipeline with an early response.

```typescript
import { UICPClient, Middleware } from '@uicp/client';

// Authentication middleware
const authMiddleware: Middleware = async (request, next) => {
  const token = await getValidToken();
  request.headers.set('Authorization', `Bearer ${token}`);
  return next(request);
};

// Logging middleware
const loggingMiddleware: Middleware = async (request, next) => {
  const start = Date.now();
  const response = await next(request);
  console.log(`${request.method} ${request.url} - ${Date.now() - start}ms`);
  return response;
};
```

## Registering Middleware

Middleware is registered at client initialization or dynamically added:

```typescript
const client = new UICPClient({
  publishableKey: 'uF1...',
  middleware: [authMiddleware, loggingMiddleware]
});

// Add middleware dynamically
client.use(cacheMiddleware);
client.use( MetricsMiddleware);
```

## Middleware Chain

Multiple middleware functions form a chain. The chain executes in registration order for requests and reverse order for responses:

```typescript
client.use(middlewareA); // First in chain
client.use(middlewareB); // Second in chain

// Request: A -> B -> API
// Response: API -> B -> A
```

## Framework Integration

The SDK provides framework-specific middleware for Express, NestJS, Fastify, and other frameworks:

### Express

```typescript
import { uicpExpressMiddleware } from '@uicp/server/express';

app.use('/api/*', uicpExpressMiddleware({
  secretKey: process.env.UICP_SECRET_KEY,
  paths: ['/api/users', '/api/projects']
}));
```

### NestJS

```typescript
@Module({
  imports: [UICPModule.forRoot({
    secretKey: process.env.UICP_SECRET_KEY
  })],
  controllers: [AppController]
})
export class AppModule {}
```

## Custom Middleware Examples

### Rate Limiting Middleware

```typescript
const rateLimitMiddleware: Middleware = async (request, next) => {
  const key = request.headers.get('X-Client-Id');
  const allowed = await checkRateLimit(key);

  if (!allowed) {
    return new Response('Rate limit exceeded', { status: 429 });
  }

  return next(request);
};
```

### Caching Middleware

```typescript
const cacheMiddleware: Middleware = async (request, next) => {
  if (request.method !== 'GET') return next(request);

  const cached = await cache.get(request.url);
  if (cached) return cached;

  const response = await next(request);
  await cache.set(request.url, response);
  return response;
};
```

---

## Related Documents

- `examples/express.md` - Express middleware example
- `examples/nestjs.md` - NestJS module configuration
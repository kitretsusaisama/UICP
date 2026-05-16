# Backend SDK

## Metadata
```yaml
title: Backend SDK
domain: sdk/backend
owner: platform-team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: LOW
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - initialization.md
  - token-handling.md
related-docs:
  - examples/nestjs.md
  - examples/express.md
  - error-handling.md
related-queues: []
related-services:
  - authentication-service
  - token-service
```

---

## Overview

The Backend SDK provides a comprehensive TypeScript client for server-side Node.js applications. It enables secure communication with UICP services, handling authentication, queue operations, and tenant management. Unlike the frontend SDK, the backend SDK uses secret keys which provide full access to the API surface.

## Installation

```bash
npm install @uicp/server
```

## Initialization

```typescript
import { UICPBackendClient } from '@uicp/server';

const client = new UICPBackendClient({
  secretKey: 'sF1abc123def456ghi789jkl012',
  tenantId: 'tenant_abc123',
  baseUrl: 'https://api.uicp.io'
});
```

## Core Capabilities

### Full API Access

The backend SDK provides access to all UICP APIs including user management, queue operations, audit logging, and administrative functions.

```typescript
// User management
const user = await client.users.create({
  identity: 'newuser@example.com',
  authMethod: 'password',
  initialPassword: 'secure_password_123'
});

// Queue operations
await client.queues.enqueue({
  queueName: 'notification-email',
  payload: {
    to: 'user@example.com',
    template: 'welcome'
  },
  priority: 'normal'
});
```

### Token Management

The SDK provides robust token management including generation, validation, and refresh operations. This is critical for implementing custom authentication flows or microservices authentication.

```typescript
const token = await client.tokens.create({
  subject: 'service_account',
  scopes: ['read:users', 'write:queue'],
  expiresIn: 3600
});

const validation = await client.tokens.validate(token);
```

### Queue Operations

Backend services can publish to and consume from UICP queues using the SDK's queue interface. This enables event-driven architectures and asynchronous processing.

## Security Best Practices

Secret keys must never be exposed in client-side code, version control, or logging systems. Use environment variables with proper rotation policies. The SDK supports key rotation without service interruption.

## Integration Patterns

The backend SDK integrates with popular Node.js frameworks including Express, NestJS, Fastify, and Koa. Middleware components simplify authentication middleware generation.

---

## Related Documents

- `examples/nestjs.md` - NestJS integration
- `examples/express.md` - Express integration
- `token-handling.md` - Token lifecycle management
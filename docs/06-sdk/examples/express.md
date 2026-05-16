# Express.js Example

## Metadata
```yaml
title: Express.js SDK Example
domain: sdk/examples
owner: platform-team
criticality: MEDIUM
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: LOW
provider-impact: NONE
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - backend-sdk.md
  - initialization.md
  - middleware.md
related-docs:
  - examples/nestjs.md
  - error-handling.md
related-queues:
  - notification-queue
related-services:
  - user-service
  - auth-service
```

---

## Overview

This guide demonstrates integrating the UICP backend SDK into an Express.js application. The example covers authentication middleware, route protection, and queue integration.

## Installation

```bash
npm install @uicp/server express
```

## SDK Initialization

Create a centralized SDK instance:

```typescript
// lib/uicp.ts
import { UICPBackendClient } from '@uicp/server';

export const client = new UICPBackendClient({
  secretKey: process.env.UICP_SECRET_KEY!,
  tenantId: process.env.UICP_TENANT_ID!,
  baseUrl: process.env.UICP_BASE_URL
});

export default client;
```

## Authentication Middleware

Implement JWT authentication middleware:

```typescript
// middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import client from '../lib/uicp';

export async function authenticate(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: 'No authorization header' });
  }

  const token = authHeader.replace('Bearer ', '');

  try {
    const user = await client.auth.verify(token);
    (req as any).user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
```

## Rate Limiting Middleware

Protect endpoints from abuse:

```typescript
// middleware/rateLimit.ts
import { Request, Response, NextFunction } from 'express';

const requestCounts = new Map<string, { count: number; resetTime: number }>();

export function rateLimit(maxRequests: number, windowMs: number) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = req.ip || 'unknown';
    const now = Date.now();

    let record = requestCounts.get(key);

    if (!record || now > record.resetTime) {
      record = { count: 0, resetTime: now + windowMs };
      requestCounts.set(key, record);
    }

    record.count++;

    if (record.count > maxRequests) {
      return res.status(429).json({ error: 'Too many requests' });
    }

    next();
  };
}
```

## Route Handlers

Create API routes using the SDK:

```typescript
// routes/users.ts
import { Router } from 'express';
import client from '../lib/uicp';
import { authenticate } from '../middleware/auth';

const router = Router();

// Get all users
router.get('/users', authenticate, async (req, res) => {
  const users = await client.users.list({
    limit: 20,
    offset: parseInt(req.query.offset as string) || 0
  });
  res.json(users);
});

// Get single user
router.get('/users/:id', authenticate, async (req, res) => {
  try {
    const user = await client.users.get(req.params.id);
    res.json(user);
  } catch (error) {
    if (error.code === 'NOT_FOUND') {
      res.status(404).json({ error: 'User not found' });
    }
    throw error;
  }
});

// Create user
router.post('/users', authenticate, async (req, res) => {
  const user = await client.users.create(req.body);
  res.status(201).json(user);
});

// Update user
router.patch('/users/:id', authenticate, async (req, res) => {
  const user = await client.users.update(req.params.id, req.body);
  res.json(user);
});

// Delete user
router.delete('/users/:id', authenticate, async (req, res) => {
  await client.users.delete(req.params.id);
  res.status(204).send();
});

export default router;
```

## Queue Integration

Process background jobs using queues:

```typescript
// routes/webhooks.ts
import { Router } from 'express';
import client from '../lib/uicp';

const router = Router();

// Enqueue a notification
router.post('/notify', async (req, res) => {
  const { userId, message } = req.body;

  await client.queues.enqueue({
    queueName: 'notification-email',
    payload: {
      to: userId,
      message
    },
    priority: 'normal'
  });

  res.json({ status: 'queued' });
});

// Health check endpoint
router.get('/health', async (req, res) => {
  const health = await client.health.check();
  res.json(health);
});

export default router;
```

## Application Setup

Combine everything in the main application:

```typescript
// app.ts
import express from 'express';
import userRoutes from './routes/users';
import webhookRoutes from './routes/webhooks';
import { authenticate } from './middleware/auth';
import { rateLimit } from './middleware/rateLimit';

const app = express();

app.use(express.json());

// Apply global rate limiting
app.use(rateLimit(100, 60000));

// Public routes
app.use('/webhooks', webhookRoutes);

// Protected routes
app.use('/api', authenticate, userRoutes);

// Error handling
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

export default app;
```

## Environment Configuration

Use environment variables for configuration:

```typescript
// .env
UICP_SECRET_KEY=sF1abc123def456ghi789
UICP_TENANT_ID=tenant_abc123
UICP_BASE_URL=https://api.uicp.io
```

---

## Related Documents

- `examples/nestjs.md` - NestJS example
- `middleware.md` - Full middleware documentation
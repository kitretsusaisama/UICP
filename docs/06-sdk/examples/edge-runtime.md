# Edge Runtime Example

## Metadata
```yaml
title: Edge Runtime SDK Example
domain: sdk/examples
owner: platform-team
criticality: MEDIUM
runtime-impact: LOW
security-impact: MEDIUM
queue-impact: NONE
provider-impact: NONE
tenant-impact: LOW
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - edge-sdk.md
  - initialization.md
  - publishable-keys.md
related-docs:
  - examples/react.md
  - middleware.md
related-queues: []
related-services: []
```

---

## Overview

This guide demonstrates using the UICP SDK in edge computing environments, specifically Cloudflare Workers and Vercel Edge Functions. Edge runtimes have unique constraints requiring specialized handling.

## Installation

```bash
npm install @uicp/edge
```

## Cloudflare Workers

Deploy authentication at the edge:

```typescript
// src/index.ts
import { UICPEdgeClient } from '@uicp/edge';

export interface Env {
  UICP_PUBLISHABLE_KEY: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const client = new UICPEdgeClient({
      publishableKey: env.UICP_PUBLISHABLE_KEY,
      baseUrl: 'https://api.uicp.io'
    });

    const url = new URL(request.url);

    // Route: /api/profiles/:id
    if (url.pathname.startsWith('/api/profiles/')) {
      const profileId = url.pathname.split('/').pop();

      // Verify authentication
      const authHeader = request.headers.get('Authorization');
      if (!authHeader) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      try {
        const profile = await client.profiles.get(profileId!);
        return new Response(JSON.stringify(profile), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
          status: error.status || 500
        });
      }
    }

    return new Response('Not Found', { status: 404 });
  }
};
```

## Vercel Edge Functions

Integration with Vercel's edge runtime:

```typescript
// app/api/user/route.ts
import { UICPEdgeClient } from '@uicp/edge';

export const runtime = 'edge';

const client = new UICPEdgeClient({
  publishableKey: process.env.UICP_PUBLISHABLE_KEY!
});

export async function GET(request: Request) {
  const authHeader = request.headers.get('Authorization');

  if (!authHeader) {
    return new Response('Unauthorized', { status: 401 });
  }

  try {
    const user = await client.users.me();
    return Response.json(user);
  } catch (error) {
    return new Response(error.message, { status: 500 });
  }
}
```

## Deno Deploy

Running on Deno Deploy:

```typescript
// main.ts
import { UICPEdgeClient } from '@uicp/edge';

const client = new UICPEdgeClient({
  publishableKey: Deno.env.get('UICP_PUBLISHABLE_KEY')!,
  baseUrl: 'https://api.uicp.io'
});

Deno.serve(async (req) => {
  const user = await client.users.me();
  return new Response(JSON.stringify(user), {
    headers: { 'Content-Type': 'application/json' }
  });
});
```

## Edge-Specific Features

### Request Caching

Leverage edge caching for improved performance:

```typescript
const client = new UICPEdgeClient({
  publishableKey: env.UICP_PUBLISHABLE_KEY,
  cache: {
    // Cache GET requests for 60 seconds at edge
    enabled: true,
    ttl: 60,
    cacheableMethods: ['GET']
  }
});
```

### Streaming Responses

Handle streaming data efficiently:

```typescript
async function handleStreamRequest(request: Request) {
  const response = await client.data.stream();

  return new Response(response.body, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Transfer-Encoding': 'chunked'
    }
  });
}
```

## Environment Configuration

Configure for different edge platforms:

```typescript
// Workers use Wrangler
// wrangler.toml
// [vars]
// UICP_PUBLISHABLE_KEY = "pB1..."

// Vercel uses env variables
// .env.local
// UICP_PUBLISHABLE_KEY=pB1...
```

## Authentication at Edge

Implement edge authentication validation:

```typescript
async function validateAuth(request: Request, client: UICPEdgeClient) {
  const cookie = request.headers.get('Cookie');
  const token = parseTokenFromCookie(cookie);

  if (!token) {
    return null;
  }

  try {
    return await client.auth.verify(token);
  } catch {
    return null;
  }
}

function parseTokenFromCookie(cookie: string | null): string | null {
  if (!cookie) return null;

  const match = cookie.match(/uicp_token=([^;]+)/);
  return match ? match[1] : null;
}
```

## Error Handling

Edge-compatible error handling:

```typescript
try {
  const result = await client.users.list();
  return new Response(JSON.stringify(result));
} catch (error) {
  return new Response(JSON.stringify({
    error: error.code || 'UNKNOWN_ERROR',
    message: error.message
  }), {
    status: error.status || 500
  });
}
```

---

## Related Documents

- `edge-sdk.md` - Full edge SDK documentation
- `publishable-keys.md` - Key types and security
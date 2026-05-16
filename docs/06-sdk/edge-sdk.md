# Edge SDK

## Metadata
```yaml
title: Edge SDK
domain: sdk/edge
owner: platform-team
criticality: HIGH
runtime-impact: LOW
security-impact: MEDIUM
queue-impact: LOW
provider-impact: NONE
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - initialization.md
  - publishable-keys.md
related-docs:
  - examples/edge-runtime.md
  - token-handling.md
related-queues: []
related-services: []
```

---

## Overview

The Edge SDK is designed for serverless and edge computing environments including Cloudflare Workers, Vercel Edge Functions, AWS Lambda@Edge, and Deno Deploy. These environments have unique constraints including limited runtime, no persistent file system, and specific API compatibility requirements.

## Installation

```bash
npm install @uicp/edge
```

## Initialization

```typescript
import { UICPEdgeClient } from '@uicp/edge';

const client = new UICPEdgeClient({
  publishableKey: 'pB1abc123def456ghi789',
  // Edge environments often have custom base URLs
  baseUrl: process.env.UICP_API_URL
});
```

## Edge-Specific Features

### Minimal Footprint

The edge SDK is optimized for minimal bundle size, typically under 15KB compressed. This is achieved through tree-shaking, dependency minimization, and avoiding Node.js-specific polyfills.

### Web Standards Compliance

All APIs use standard Web APIs including fetch, URL, and Web Crypto. This ensures compatibility across edge runtimes without requiring Node.js compatibility layers.

### Streaming Support

Edge functions often need to handle streaming responses. The SDK supports both buffered and streaming response handling.

```typescript
// Streaming response handling
const response = await client.notifications.stream();
const reader = response.body.getReader();

while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  // Process chunk
}
```

## Limitations

Certain features are unavailable or limited in edge environments due to platform constraints:

- WebSocket connections require specific edge adapter usage
- Persistent storage relies on external key-value stores
- Long-running operations may be terminated by platform limits

## Use Cases

The edge SDK excels at authentication verification, request middleware, and lightweight API proxying at the edge.

```typescript
export default {
  async fetch(request: Request): Promise<Response> {
    const client = new UICPEdgeClient({ publishableKey: env.PUBLISHABLE_KEY });

    // Verify authentication at the edge
    const authHeader = request.headers.get('Authorization');
    if (authHeader) {
      const user = await client.auth.verify(authHeader.replace('Bearer ', ''));
      // Process authenticated request
    }

    return new Response('Unauthorized', { status: 401 });
  }
};
```

---

## Related Documents

- `examples/edge-runtime.md` - Cloudflare Workers example
- `publishable-keys.md` - Key types and security
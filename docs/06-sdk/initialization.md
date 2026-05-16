# SDK Initialization

## Metadata
```yaml
title: SDK Initialization
domain: sdk/initialization
owner: platform-team
criticality: HIGH
runtime-impact: LOW
security-impact: HIGH
queue-impact: NONE
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - publishable-keys.md
  - token-handling.md
related-docs:
  - frontend-sdk.md
  - backend-sdk.md
  - edge-sdk.md
related-queues: []
related-services:
  - auth-service
```

---

## Overview

SDK initialization configures the client with necessary credentials and settings. Proper initialization ensures secure, reliable communication with UICP services. The initialization process differs slightly between frontend, backend, and edge SDKs based on their security models.

## Frontend Initialization

The frontend SDK uses publishable keys which are safe to embed in client-side code. However, best practices recommend loading configuration from environment variables.

```typescript
import { UICPClient } from '@uicp/client';

const client = new UICPClient({
  publishableKey: process.env.NEXT_PUBLIC_UICP_PUBLISHABLE_KEY,
  baseUrl: process.env.NEXT_PUBLIC_UICP_BASE_URL || 'https://api.uicp.io',
  timeout: 30000,
  retries: 3
});
```

## Backend Initialization

Backend initialization requires secret keys which must be protected rigorously. Never hardcode secrets; always use environment variables or secrets management systems.

```typescript
import { UICPBackendClient } from '@uicp/server';

const client = new UICPBackendClient({
  secretKey: process.env.UICP_SECRET_KEY,
  tenantId: process.env.UICP_TENANT_ID,
  baseUrl: process.env.UICP_BASE_URL,
  // Advanced: custom HTTP agent for proxy support
  agent: new https.Agent({
    keepAlive: true,
    maxSockets: 100
  })
});
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| publishableKey/secretKey | string | required | Authentication credential |
| tenantId | string | inferred | Explicit tenant identifier |
| baseUrl | string | https://api.uicp.io | API endpoint |
| timeout | number | 30000 | Request timeout in milliseconds |
| retries | number | 3 | Automatic retry attempts |
| logger | object | console | Custom logger implementation |

## Environment-Specific URLs

Different environments require different API endpoints. Configure base URLs appropriately for development, staging, and production:

- Development: https://api.sandbox.uicp.io
- Staging: https://api.staging.uicp.io
- Production: https://api.uicp.io

## Initialization Verification

After initialization, verify the client is properly configured by checking the connection:

```typescript
const health = await client.health.check();
if (!health.ok) {
  throw new Error('UICP client initialization failed');
}
```

---

## Related Documents

- `publishable-keys.md` - Key types and security boundaries
- `token-handling.md` - Token management configuration
- `error-handling.md` - Initialization error handling
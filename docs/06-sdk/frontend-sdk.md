# Frontend SDK

## Metadata
```yaml
title: Frontend SDK
domain: sdk/frontend
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
  - initialization.md
  - publishable-keys.md
related-docs:
  - examples/nextjs.md
  - examples/react.md
  - examples/react-native.md
related-queues: []
related-services: []
```

---

## Overview

The Frontend SDK provides a lightweight JavaScript/TypeScript client for browser-based applications. It is designed for seamless integration with React, Vue, Angular, and vanilla JavaScript projects. The SDK handles authentication, token management, and API communication while maintaining strict security boundaries by enforcing publishable key restrictions.

## Installation

```bash
npm install @uicp/client
```

## Core Features

### Client Initialization

The frontend SDK requires only a publishable key for initialization. This key identifies your tenant and configures the client for your specific environment.

```typescript
import { UICPClient } from '@uicp/client';

const client = new UICPClient({
  publishableKey: 'uF1abc123def456ghi789',
  baseUrl: 'https://api.uicp.io'
});
```

### Authentication

The SDK exposes an authentication module that supports multiple methods including password-based login, magic links, and OAuth providers. All authentication flows return access tokens that are automatically managed by the SDK.

```typescript
// Password-based authentication
const { accessToken, refreshToken, expiresIn } = await client.auth.attempt({
  identity: 'user@example.com',
  authMethod: 'password',
  secret: 'secure_password'
});
```

### Session Management

The SDK automatically handles session state including token storage, refresh cycles, and logout propagation. Sessions are persisted using secure storage mechanisms appropriate for each platform.

### API Client

All HTTP communication flows through the centralized API client which applies authentication headers, handles retry logic, and transforms responses.

```typescript
const user = await client.users.me();
const projects = await client.projects.list();
```

## Security Considerations

The frontend SDK operates under strict security constraints. Publishable keys cannot access secret operations, administrative functions, or modify sensitive tenant configuration. All token storage uses HttpOnly cookies where supported, with fallback to encrypted local storage for legacy browsers.

## TypeScript Support

Full TypeScript definitions are included with comprehensive type safety for all API responses, request parameters, and configuration options.

---

## Related Documents

- `initialization.md` - Detailed initialization options
- `publishable-keys.md` - Key types and security boundaries
- `examples/react.md` - React integration guide
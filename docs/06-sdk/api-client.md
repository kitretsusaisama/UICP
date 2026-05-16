# API Client

## Metadata
```yaml
title: API Client
domain: sdk/api
owner: platform-team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: NONE
provider-impact: NONE
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - sdk-overview.md
  - initialization.md
  - token-handling.md
related-docs:
  - frontend-sdk.md
  - backend-sdk.md
  - retry-behavior.md
related-queues: []
related-services:
  - api-gateway
```

---

## Overview

The API Client is the core component responsible for all HTTP communication between the SDK and UICP services. It handles request construction, authentication injection, response parsing, and error transformation.

## Request Construction

The SDK provides a fluent interface for building API requests:

```typescript
// Simple GET request
const user = await client.users.get('user_123');

// Request with options
const users = await client.users.list({
  limit: 20,
  offset: 0,
  filter: { status: 'active' },
  sort: { createdAt: 'desc' }
});

// POST request with body
const newProject = await client.projects.create({
  name: 'New Project',
  description: 'Project description'
});
```

## Authentication Injection

The API Client automatically injects authentication credentials into all requests:

```typescript
// Access token added automatically
const response = await client.api.get('/users/me');
// Headers: Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

For backend SDKs using secret keys, the authentication header differs:

```typescript
// Secret key authentication
const response = await client.api.get('/admin/users');
// Headers: X-UICP-Key: sF1abc123...
```

## Response Handling

All responses are transformed into typed objects with metadata:

```typescript
const response = await client.users.list({ limit: 10 });

console.log(response.data);     // User[]
console.log(response.meta);    // { total: 100, page: 1 }
console.log(response.pagination.next); // Cursor for next page
```

## Custom Requests

For operations not covered by the typed API, custom requests are supported:

```typescript
// Custom GET
const result = await client.api.get('/custom-endpoint', {
  params: { key: 'value' }
});

// Custom POST with custom headers
const result = await client.api.post('/webhook', {
  body: { event: 'update' },
  headers: { 'X-Custom-Header': 'value' }
});
```

## Interceptors

Request and response interceptors provide powerful customization:

```typescript
client.api.interceptors.request.use((config) => {
  config.headers.set('X-Client-Version', appVersion);
  return config;
});

client.api.interceptors.response.use(
  (response) => response,        // Success handler
  (error) => {                   // Error handler
    if (error.status === 401) {
      // Handle unauthorized
    }
    throw error;
  }
);
```

## Base URL Configuration

The API client uses the base URL configured during initialization, but can be overridden per request:

```typescript
const response = await client.api.get('/users', {
  baseUrl: 'https://alternate-api.uicp.io'
});
```

---

## Related Documents

- `token-handling.md` - Token management in requests
- `retry-behavior.md` - Automatic retry configuration
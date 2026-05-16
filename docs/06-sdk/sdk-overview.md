# SDK Overview

## Metadata
```yaml
title: SDK Overview
domain: sdk
criticality: HIGH
ai-ingestable: true
```

---

## Overview

UICP provides SDKs for easy integration into applications.

---

## Supported Platforms

| SDK | Status | Language |
|-----|--------|----------|
| Frontend (Web) | 🏗️ Roadmap | JavaScript/TypeScript |
| Backend (Node) | 🏗️ Roadmap | TypeScript |
| Edge | 🏗️ Roadmap | JavaScript |
| Mobile | 🏗️ Roadmap | React Native |

---

## Key Concepts

### Publishable Keys
- Start with `uF` (live) or `pB` (dev)
- Safe to embed in client-side code
- Cannot access secret operations

### Secret Keys
- Start with `sF` (live) or `tB` (dev)
- NEVER expose in client code
- Server-side only

### Authentication Flow

```javascript
// Client-side
const client = new UICPClient({ publishableKey: 'uF...' });

// Authenticate
const { accessToken } = await client.auth.attempt({
  identity: 'user@example.com',
  authMethod: 'password',
  secret: 'password'
});

// Make authenticated request
const user = await client.users.me();
```

---

## Related Documents

- `06-sdk/frontend-sdk.md`
- `06-sdk/backend-sdk.md`
- `06-sdk/initialization.md`


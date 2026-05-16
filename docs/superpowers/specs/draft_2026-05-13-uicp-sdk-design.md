# UICP SDK Design Specification

**Date**: 2026-05-13
**Status**: Approved
**Version**: 1.0

---

## 1. Package Overview

**Package Name**: `@uicp/sdk`
**Type**: Single npm package (no monorepo)
**Target Runtimes**: Node 18+, Browser, Cloudflare Workers, Vercel Edge, Deno
**Output**: ESM + CJS via tsup

---

## 2. Package Structure

```
@uicp/sdk/
├── src/
│   ├── index.ts                 ← barrel export
│   ├── client.ts                ← UICPClient class + builder
│   ├── types.ts                 ← all exported types
│   ├── errors.ts                ← error hierarchy
│   ├── token-vault.ts           ← token storage + expiry logic
│   ├── event-bus.ts             ← typed event emitter
│   ├── http/
│   │   ├── pipeline.ts          ← fetch wrapper
│   │   ├── adapters/
│   │   │   ├── fetch.adapter.ts ← default
│   │   │   └── axios.adapter.ts ← optional
│   │   └── interceptors/
│   │       ├── auth.interceptor.ts
│   │       ├── tenant.interceptor.ts
│   │       ├── idempotency.interceptor.ts
│   │       ├── refresh.interceptor.ts
│   │       ├── retry.interceptor.ts
│   │       └── rate-limit.interceptor.ts
│   ├── storage/
│   │   ├── memory.adapter.ts    ← default
│   │   ├── local-storage.adapter.ts
│   │   └── cookie.adapter.ts
│   └── modules/
│       ├── auth.client.ts
│       ├── user.client.ts
│       ├── session.client.ts
│       ├── core.client.ts
│       ├── admin.client.ts
│       ├── platform.client.ts
│       ├── dynamic-modules.client.ts
│       └── extensions.client.ts
├── package.json
├── tsconfig.json
└── README.md
```

---

## 3. Core API

### 3.1 Client Creation

```typescript
import { UICPClient } from '@uicp/sdk'

// Minimal
const client = UICPClient.create({
  baseUrl: 'https://api.example.com',
  tenantId: '00000000-0000-0000-0000-000000000000',
})

// Builder (fluent)
const client = UICPClient.builder()
  .withBaseUrl('https://api.example.com')
  .withTenantId('00000000-0000-0000-0000-000000000000')
  .withStorage(new MemoryAdapter())
  .withDebug(true)
  .onSessionExpired(() => router.push('/login'))
  .build()
```

### 3.2 Sub-Clients

```typescript
client.auth          // AuthClient
client.user          // UserClient
client.session       // SessionClient
client.core          // CoreClient
client.admin         // AdminClient
client.platform      // PlatformClient
client.modules       // DynamicModuleClient
client.extensions    // ExtensionClient
client.missing       // MissingAPIs stubs
```

---

## 4. Token Lifecycle

| Event | SDK Action |
|-------|------------|
| `login()` success | `vault.setTokens()` + emit `tokens:set` |
| `refresh()` success | Replace tokens + emit `tokens:set` |
| `logout()` success | `vault.clearTokens()` + emit `tokens:cleared` |
| Token expired | Auto-refresh before request |
| 401 + TOKEN_REUSE_DETECTED | Clear tokens + emit `session:expired` + throw |

---

## 5. Error Hierarchy

```typescript
UICPError                    // base
├── UICPRateLimitError       // 429 with rateLimitTier
├── UICPSessionExpiredError  // 401 + token reuse
├── UICPNotImplementedError  // 501 for missing APIs
└── UICPNetworkError         // 0 for network failures
```

---

## 6. Missing API Stubs

```typescript
client.missing.tokenIntrospect(token)      // throws UICPNotImplementedError
client.missing.exportAuditLogs()          // throws UICPNotImplementedError
client.missing.adminRevokeDevice(...)     // throws UICPNotImplementedError
client.missing.socAlertSubscribe()        // throws UICPNotImplementedError
```

---

## 7. Implementation Order

1. **Types & Errors** — types.ts, errors.ts
2. **Token Vault** — token-vault.ts with expiry logic
3. **Event Bus** — event-bus.ts
4. **Storage Adapters** — MemoryAdapter, LocalStorageAdapter, CookieAdapter
5. **HTTP Layer** — fetch adapter, interceptors
6. **Module Clients** — auth, user, session, core, admin, platform, modules, extensions
7. **UICPClient** — client.ts tying everything together
8. **Index & Package** — index.ts, package.json, tsconfig.json, README.md

---

## 8. Acceptance Criteria

- [x] Design approved
- [ ] `UICPClient.create()` and `UICPClient.builder()` work
- [ ] All 8 sub-clients accessible
- [ ] Token auto-refresh on expiry
- [ ] Token auto-clear on logout/changePassword/deleteMe
- [ ] Token auto-store on login/oauth/switchActor
- [ ] No retry on POST /auth/refresh (non-idempotent)
- [ ] Auto idempotency keys on COST CRITICAL endpoints
- [ ] Missing APIs throw UICPNotImplementedError
- [ ] ESM + CJS output
- [ ] TypeScript strict mode
# UICP SDK — MASTER GENERATION PROMPT
# Version: 2.0 | Strict Contract Mode | No Assumptions | No Hallucinations

---

## ╔══ MISSION ══╗

You are a principal TypeScript SDK architect. Your job is to generate the
complete, production-grade, npm-publishable SDK for the Unified Identity
Control Plane (UICP). The SDK must be:

- Strictly grounded in the API contract below — invent NOTHING
- Runtime-agnostic: Node 18+, Browser, Cloudflare Workers, Vercel Edge, Deno
- Fully isomorphic: zero platform-specific globals in core packages
- Tree-shakeable: every sub-client is independently importable
- 100x DX: autocomplete on every parameter, return type, and error code
- Monorepo structure: separate packages for core, react, testing, types

---

## ╔══ MONOREPO STRUCTURE ══╗

```
packages/
  @uicp/types/          ← pure types, zero runtime, zero deps
  @uicp/core/           ← UICPClient + all sub-clients (no framework deps)
  @uicp/react/          ← React hooks + Context (peer dep: react ≥17)
  @uicp/testing/        ← MockUICPClient + test utilities

Root toolchain: pnpm workspaces, tsup for bundling, vitest for tests,
changesets for versioning, publint for npm validation.
```

Each package ships:
- `dist/index.cjs`   (CommonJS)
- `dist/index.mjs`   (ESM)
- `dist/index.d.ts`  (TypeScript declarations)

`package.json` exports map:
```json
{
  "exports": {
    ".": {
      "import": "./dist/index.mjs",
      "require": "./dist/index.cjs",
      "types": "./dist/index.d.ts"
    }
  },
  "sideEffects": false
}
```

---

## ╔══ PACKAGE: @uicp/types ══╗

Zero runtime. All types, interfaces, enums as const objects (not TS enums).
Export everything from `src/index.ts`.

### Core domain types (strictly from contract — no invented fields)

```typescript
// ── Tenant ──────────────────────────────────────────────────────────────────
export type TenantId = string & { readonly __brand: 'TenantId' }
export const asTenantId = (id: string): TenantId => id as TenantId

// ── Tokens ───────────────────────────────────────────────────────────────────
export interface TokenSet {
  accessToken: string
  refreshToken: string
  sessionId: string
  expiresIn: number      // seconds, from server
}
export interface RefreshTokenSet {
  accessToken: string
  refreshToken: string
  expiresIn: number
}

// ── Auth responses ────────────────────────────────────────────────────────────
export interface SignupResponse {
  userId: string
  message: string
}
export interface LoginResponse extends TokenSet {}
export interface SwitchActorResponse {
  accessToken: string
  actor: Record<string, unknown>
  effectiveCapabilitiesVersion: string
}
export interface OtpVerifyResponse {
  verified: true
  userStatus: string
}

// ── OTP ──────────────────────────────────────────────────────────────────────
// NOTE: purpose and channel values are NOT specified in the contract.
// They are typed as string. Do NOT invent enum values.
export interface SendOtpInput {
  purpose: string
  channel: string
  identity: string
}
export interface VerifyOtpInput {
  userId: string
  code: string
  purpose: string
  identityId?: string
  sessionId?: string
}

// ── Password ──────────────────────────────────────────────────────────────────
// NOTE: field names inside these schemas are NOT specified in the contract.
// Type as Record<string, unknown> and document with @contract.
/** @contract body schema = changePasswordSchema (zod, server-side). Fields unspecified. */
export type ChangePasswordInput = Record<string, unknown>
/** @contract body schema = passwordResetRequestSchema (zod, server-side). Fields unspecified. */
export type PasswordResetRequestInput = Record<string, unknown>
/** @contract body schema = passwordResetConfirmSchema (zod, server-side). Fields unspecified. */
export type PasswordResetConfirmInput = Record<string, unknown>
/** @contract body schema = patchUserSchema (zod, server-side). Fields unspecified. */
export type PatchUserInput = Record<string, unknown>
/** @contract body schema = addIdentitySchema (zod, server-side). Fields unspecified. */
export type AddIdentityInput = Record<string, unknown>

// ── Generic API envelope ──────────────────────────────────────────────────────
export interface ApiSuccess<T> { data: T }
export interface ApiError { error: { code: string; message: string } }

// ── IAM rate limit tiers (from contract §07) ──────────────────────────────────
export const RateLimitTier = {
  SIGNUP: 'signup',
  LOGIN: 'login',
  REFRESH: 'refresh',
  LOGOUT: 'logout',
  LOGOUT_ALL: 'logout-all',
  OTP_SEND: 'otp-send',
  OTP_VERIFY: 'otp-verify',
  PW_RESET: 'pw-reset',
  PW_RESET_CONFIRM: 'pw-reset-confirm',
} as const
export type RateLimitTier = typeof RateLimitTier[keyof typeof RateLimitTier]

// ── Risk levels (from contract §07) ──────────────────────────────────────────
export const RiskLevel = {
  NORMAL: 'NORMAL',
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  COST_CRITICAL: 'COST_CRITICAL',
  AUTH_CRITICAL: 'AUTH_CRITICAL',
} as const
export type RiskLevel = typeof RiskLevel[keyof typeof RiskLevel]
```

---

## ╔══ PACKAGE: @uicp/core — ARCHITECTURE ══╗

### File structure

```
src/
  index.ts                      ← barrel export
  client.ts                     ← UICPClient class + builder
  errors.ts                     ← error hierarchy
  token-vault.ts                ← token lifecycle
  event-bus.ts                  ← typed event emitter
  plugin-registry.ts            ← middleware/plugin system
  retry-policy.ts               ← per-endpoint retry config
  http/
    pipeline.ts                 ← compose interceptors into fetch fn
    interceptors/
      auth.interceptor.ts       ← inject Authorization header
      tenant.interceptor.ts     ← inject x-tenant-id header
      idempotency.interceptor.ts← auto idempotency keys
      refresh.interceptor.ts    ← transparent 401 token refresh
      retry.interceptor.ts      ← idempotent-safe retry
      rate-limit.interceptor.ts ← 429 backoff
      telemetry.interceptor.ts  ← traceparent header propagation
    adapters/
      fetch.adapter.ts          ← native fetch (default, edge-safe)
      axios.adapter.ts          ← optional
      node-http.adapter.ts      ← optional
  storage/
    memory.adapter.ts           ← default, SSR-safe
    local-storage.adapter.ts    ← browser
    cookie.adapter.ts           ← httpOnly / SSR / edge
    types.ts                    ← IStorageAdapter interface
  modules/
    auth.client.ts
    user.client.ts
    session.client.ts
    core.client.ts
    admin.client.ts
    platform.client.ts
    dynamic-modules.client.ts
    extensions.client.ts
```

---

## ╔══ ERROR HIERARCHY ══╗

```typescript
// src/errors.ts

export class UICPError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode: number,
    public readonly raw?: unknown,
  ) {
    super(message)
    this.name = 'UICPError'
  }
}

// Thrown on HTTP 429. rateLimitTier comes from the endpoint metadata, not
// from the server response (server does not document a response field for it).
export class UICPRateLimitError extends UICPError {
  constructor(
    code: string,
    message: string,
    public readonly rateLimitTier: string,
    public readonly retryAfterMs?: number,
  ) {
    super(code, message, 429)
    this.name = 'UICPRateLimitError'
  }
}

// Thrown when a refresh token reuse is detected (server emits TokenReuseDetected).
// The SDK clears all tokens and emits 'session:expired' before throwing.
export class UICPSessionExpiredError extends UICPError {
  constructor() {
    super('TOKEN_REUSE_DETECTED', 'Session expired due to token reuse.', 401)
    this.name = 'UICPSessionExpiredError'
  }
}

// Thrown when a caller invokes a method for a MISSING API (§09 of contract).
export class UICPNotImplementedError extends UICPError {
  constructor(apiName: string, reason: string) {
    super('NOT_IMPLEMENTED', `${apiName}: ${reason}`, 501)
    this.name = 'UICPNotImplementedError'
  }
}

// Thrown when a network error occurs (non-HTTP failure).
export class UICPNetworkError extends UICPError {
  constructor(cause: unknown) {
    super('NETWORK_ERROR', 'Network request failed.', 0, cause)
    this.name = 'UICPNetworkError'
  }
}
```

---

## ╔══ TOKEN VAULT ══╗

```typescript
// src/token-vault.ts

export interface IStorageAdapter {
  get(key: string): string | null | Promise<string | null>
  set(key: string, value: string): void | Promise<void>
  delete(key: string): void | Promise<void>
  clear(): void | Promise<void>
}

export interface TokenVaultConfig {
  storage: IStorageAdapter
  // If true, SDK stores expiresAt = Date.now() + (expiresIn * 1000) - 30_000
  // (30 second buffer before actual expiry to proactively refresh)
  earlyRefreshBufferMs?: number   // default: 30_000
}

export class TokenVault {
  // Internal keys (not exported):
  // 'uicp.access_token', 'uicp.refresh_token', 'uicp.session_id', 'uicp.expires_at'

  async setTokens(tokens: TokenSet): Promise<void>
  async getAccessToken(): Promise<string | null>
  async getRefreshToken(): Promise<string | null>
  async getSessionId(): Promise<string | null>
  async isAccessTokenExpired(): Promise<boolean>
  async clearTokens(): Promise<void>
}
```

**Expiry logic** (strictly as specified):
- `expiresAt = Date.now() + (expiresIn * 1000) - earlyRefreshBufferMs`
- `isAccessTokenExpired()` returns `true` if `Date.now() >= expiresAt`

---

## ╔══ TYPED EVENT BUS ══╗

```typescript
// src/event-bus.ts
// All events grounded strictly in contract behavior:

export interface UICPEventMap {
  // Fired when login/refresh/oauthCallback succeeds and tokens are stored
  'tokens:set':          { accessToken: string; sessionId: string }
  // Fired when logout / logoutAll / deleteMe / changePassword clears tokens
  'tokens:cleared':      void
  // Fired when token reuse is detected (server-side TokenReuseDetected event)
  // After this event, tokens are already cleared.
  'session:expired':     { reason: 'TOKEN_REUSE_DETECTED' }
  // Fired before every HTTP request (for logging/telemetry)
  'request:before':      { method: string; path: string }
  // Fired after every HTTP response
  'request:after':       { method: string; path: string; statusCode: number; durationMs: number }
  // Fired when a 429 is received
  'rate-limit:hit':      { tier: RateLimitTier; retryAfterMs: number }
  // Fired when any UICPError is thrown
  'error':               UICPError
}

export class EventBus {
  on<K extends keyof UICPEventMap>(event: K, handler: (payload: UICPEventMap[K]) => void): () => void
  off<K extends keyof UICPEventMap>(event: K, handler: (payload: UICPEventMap[K]) => void): void
  once<K extends keyof UICPEventMap>(event: K, handler: (payload: UICPEventMap[K]) => void): () => void
  emit<K extends keyof UICPEventMap>(event: K, payload: UICPEventMap[K]): void
}
```

---

## ╔══ PLUGIN / INTERCEPTOR PIPELINE ══╗

```typescript
// src/plugin-registry.ts

export interface RequestContext {
  method: string
  url: string
  headers: Record<string, string>
  body?: unknown
  // Metadata injected by the SDK — not sent over the wire
  meta: {
    isIdempotent: boolean
    rateLimitTier?: RateLimitTier
    riskLevel: RiskLevel
    requiresAuth: boolean
  }
}

export interface ResponseContext<T = unknown> {
  statusCode: number
  data: T
  headers: Record<string, string>
  durationMs: number
}

export interface UICPPlugin {
  name: string
  // Called before the HTTP request is sent. Can mutate ctx.headers.
  beforeRequest?: (ctx: RequestContext) => RequestContext | Promise<RequestContext>
  // Called after a successful response. Can transform data.
  afterResponse?: <T>(ctx: ResponseContext<T>) => ResponseContext<T> | Promise<ResponseContext<T>>
  // Called on any UICPError before it is thrown. Can log, transform, or suppress.
  onError?: (error: UICPError, ctx: RequestContext) => void | Promise<void>
}

export class PluginRegistry {
  register(plugin: UICPPlugin): void
  unregister(pluginName: string): void
  runBeforeRequest(ctx: RequestContext): Promise<RequestContext>
  runAfterResponse<T>(ctx: ResponseContext<T>): Promise<ResponseContext<T>>
  runOnError(error: UICPError, ctx: RequestContext): Promise<void>
}
```

**Built-in plugins (always registered, non-removable):**
1. `TenantHeaderPlugin` — injects `x-tenant-id` from config
2. `AuthHeaderPlugin` — injects `Authorization: Bearer <token>` on auth-required routes
3. `IdempotencyPlugin` — injects `x-idempotency-key` on eligible routes (see rules below)
4. `TokenRefreshPlugin` — intercepts 401 responses, calls refresh, retries once
5. `RetryPlugin` — retries idempotent requests on network error (max 2, backoff: 100ms, 200ms)
6. `RateLimitPlugin` — intercepts 429, reads `Retry-After` header, throws `UICPRateLimitError`

**User plugins** are called after built-in plugins in registration order.

---

## ╔══ IDEMPOTENCY KEY RULES ══╗

From contract: server uses `@UseInterceptors(IdempotencyInterceptor)` on
specific endpoints. The SDK must:

**Auto-generate a UUID v4 idempotency key for COST CRITICAL endpoints only:**
  - POST /auth/signup
  - POST /users/me/identities
  - POST /auth/password/reset/request

**Send consumer-provided key if supplied via `options.idempotencyKey` for
any endpoint marked `Idempotent: YES` in the contract.**

**Header name:** `x-idempotency-key`

**Do NOT send idempotency keys** for endpoints marked `Idempotent: NO`:
  - POST /auth/refresh
  - POST /auth/otp/send
  - POST /auth/otp/verify

---

## ╔══ RETRY RULES ══╗

From contract analysis:
- `POST /auth/refresh` → Idempotent: NO → **NEVER retry on network error**
- `POST /auth/otp/send` → Idempotent: NO → **NEVER retry**
- `POST /auth/otp/verify` → Idempotent: NO → **NEVER retry** (code is consumed)
- All `Idempotent: YES` endpoints → retry up to 2 times on network error only
  with backoff: attempt 1 after 100ms, attempt 2 after 200ms

**Do NOT retry on any HTTP 4xx response — only on network-level failures.**

---

## ╔══ UICPClient — BUILDER PATTERN ══╗

```typescript
// src/client.ts

export interface UICPClientConfig {
  baseUrl: string
  tenantId: TenantId
  storage?: IStorageAdapter           // default: MemoryAdapter
  httpAdapter?: IHttpAdapter          // default: FetchAdapter
  earlyRefreshBufferMs?: number       // default: 30_000
  plugins?: UICPPlugin[]              // user plugins
  debug?: boolean                     // logs request/response to console if true
  // Called when session expires due to token reuse.
  // Fired AFTER 'session:expired' event and AFTER tokens are cleared.
  onSessionExpired?: () => void
}

// Fluent builder — all methods return `this` for chaining
export class UICPClientBuilder {
  withBaseUrl(url: string): this
  withTenantId(id: string): this
  withStorage(adapter: IStorageAdapter): this
  withHttpAdapter(adapter: IHttpAdapter): this
  withPlugin(plugin: UICPPlugin): this
  withEarlyRefreshBuffer(ms: number): this
  withDebug(enabled?: boolean): this
  onSessionExpired(callback: () => void): this
  build(): UICPClient
}

export class UICPClient {
  // Factory — preferred entry point
  static create(config: UICPClientConfig): UICPClient
  // Builder — for complex setups
  static builder(): UICPClientBuilder

  // Sub-clients (lazy-initialized, memoized)
  readonly auth:       AuthClient
  readonly user:       UserClient
  readonly session:    SessionClient
  readonly core:       CoreClient
  readonly admin:      AdminClient
  readonly platform:   PlatformClient
  readonly modules:    DynamicModuleClient
  readonly extensions: ExtensionClient

  // Token management (public API)
  setTokens(tokens: TokenSet): Promise<void>
  clearTokens(): Promise<void>
  getAccessToken(): Promise<string | null>
  isAuthenticated(): Promise<boolean>

  // Events
  readonly events: EventBus

  // Plugin management (post-init)
  use(plugin: UICPPlugin): void
}
```

**Usage example (attach to JSDoc):**
```typescript
// Minimal
const client = UICPClient.create({
  baseUrl: 'https://api.example.com',
  tenantId: asTenantId('00000000-0000-0000-0000-000000000000'),
})

// Full builder
const client = UICPClient.builder()
  .withBaseUrl('https://api.example.com')
  .withTenantId('00000000-0000-0000-0000-000000000000')
  .withStorage(new LocalStorageAdapter())
  .withPlugin(myLogPlugin)
  .onSessionExpired(() => router.push('/login'))
  .withDebug(process.env.NODE_ENV === 'development')
  .build()
```

---

## ╔══ STORAGE ADAPTERS ══╗

```typescript
// src/storage/types.ts
export interface IStorageAdapter {
  get(key: string): MaybePromise<string | null>
  set(key: string, value: string): MaybePromise<void>
  delete(key: string): MaybePromise<void>
  clear(): MaybePromise<void>
}
type MaybePromise<T> = T | Promise<T>

// src/storage/memory.adapter.ts
// In-memory Map. Default. Zero deps. Works everywhere.
export class MemoryAdapter implements IStorageAdapter { ... }

// src/storage/local-storage.adapter.ts
// Wraps window.localStorage. Throws at construction if window is undefined.
// Use only in browser environments.
export class LocalStorageAdapter implements IStorageAdapter { ... }

// src/storage/cookie.adapter.ts
// For SSR / Edge / httpOnly cookie flows.
// Constructor accepts:
//   getCookie: (name: string) => string | null
//   setCookie: (name: string, value: string, options?: CookieOptions) => void
//   deleteCookie: (name: string) => void
// This allows any SSR framework (Next.js, Nuxt, SvelteKit) to plug in.
export class CookieAdapter implements IStorageAdapter { ... }
```

---

## ╔══ HTTP ADAPTER INTERFACE ══╗

```typescript
// src/http/adapters/types.ts
export interface HttpRequest {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE'
  url: string
  headers: Record<string, string>
  body?: unknown
}
export interface HttpResponse<T = unknown> {
  statusCode: number
  data: T
  headers: Record<string, string>
}
export interface IHttpAdapter {
  request<T>(req: HttpRequest): Promise<HttpResponse<T>>
}

// src/http/adapters/fetch.adapter.ts
// Default. Uses native globalThis.fetch. Works in Browser, Node 18+,
// Cloudflare Workers, Vercel Edge, Deno.
export class FetchAdapter implements IHttpAdapter { ... }

// src/http/adapters/axios.adapter.ts
// Optional. Peer dep: axios ≥1.0.
// @experimental
export class AxiosAdapter implements IHttpAdapter { ... }
```

---

## ╔══ MODULE: AUTH CLIENT ══╗

Strictly implements §01_HTTP_APIS → AuthModule from contract.
All endpoints, side effects, and risk levels documented in JSDoc.

```typescript
// src/modules/auth.client.ts

export interface RequestOptions {
  idempotencyKey?: string
  signal?: AbortSignal
}

export class AuthClient {
  /**
   * Register a new user with phone or email.
   *
   * @contract POST /api/v1/auth/signup
   * @risk HIGH
   * @rateTier signup (COST CRITICAL)
   * @idempotent YES — auto-generates idempotency key if none provided
   * @sideEffects DB: INSERT users, identities, credentials | Redis: SET otp | Queue: otp-send
   */
  signup(body: SignupInput, options?: RequestOptions): Promise<SignupResponse>

  /**
   * Authenticate with identifier + credential.
   * On success, tokens are stored in the configured TokenVault automatically.
   *
   * @contract POST /api/v1/auth/login
   * @risk AUTH_CRITICAL
   * @rateTier login (AUTH CRITICAL)
   * @idempotent YES
   * @sideEffects DB: update user status, last login | Redis: SessionService.createSession | Queue: LoginSucceeded / ThreatDetected outbox event
   * @external Maxmind GeoIP (local DB lookup)
   */
  login(body: LoginInput, options?: RequestOptions): Promise<LoginResponse>

  /**
   * Rotate the refresh token and receive a new access + refresh token pair.
   * Called automatically by the SDK's token refresh interceptor.
   *
   * @contract POST /api/v1/auth/refresh
   * @risk AUTH_CRITICAL
   * @rateTier refresh (AUTH CRITICAL)
   * @idempotent NO — rotation is inherently mutating. DO NOT retry on network error.
   * @sideEffects DB: revoke old refresh token, insert new refresh token | Queue: TokenRefreshed / TokenReuseDetected
   * @warning If TokenReuseDetected (401), the SDK clears all tokens and emits 'session:expired'
   */
  refresh(body: { refreshToken: string }, options?: RequestOptions): Promise<RefreshTokenSet>

  /**
   * Invalidate the current session.
   * On success, tokens are cleared from the TokenVault automatically.
   *
   * @contract POST /api/v1/auth/logout
   * @risk LOW
   * @rateTier logout
   * @idempotent YES
   * @sideEffects Redis: delete session HASH, remove from ZSET, add JTI to blocklist | Queue: LogoutRequested outbox
   */
  logout(options?: RequestOptions): Promise<{ loggedOut: true }>

  /**
   * Invalidate ALL sessions for the current user across all devices.
   * On success, tokens are cleared from the TokenVault automatically.
   *
   * @contract POST /api/v1/auth/logout-all
   * @risk MEDIUM
   * @rateTier logout-all
   * @idempotent YES
   * @sideEffects DB: revokeAllFamiliesByUser | Redis: evict all sessions, blocklist all active JTIs
   */
  logoutAll(options?: RequestOptions): Promise<{ loggedOut: true }>

  /**
   * Send an OTP to the user via the specified channel.
   *
   * @contract POST /api/v1/auth/otp/send
   * @risk COST_CRITICAL
   * @rateTier otp-send
   * @idempotent NO
   * @sideEffects Redis: SET otp code | Queue: otp-send → FirebaseOtpAdapter (SMS) or SMTP
   * @warning SMS has no fallback provider. SMTP has multi-provider routing.
   */
  sendOtp(body: SendOtpInput, options?: RequestOptions): Promise<{ sent: true }>

  /**
   * Verify an OTP code. The code is atomically consumed (GETDEL) server-side.
   *
   * @contract POST /api/v1/auth/otp/verify
   * @risk AUTH_CRITICAL
   * @rateTier otp-verify
   * @idempotent NO — code is consumed on first use, replay is rejected
   * @sideEffects DB: UPDATE users / identities | Redis: GETDEL otp code | Queue: outbox
   */
  verifyOtp(body: VerifyOtpInput, options?: RequestOptions): Promise<OtpVerifyResponse>

  /**
   * Switch the active actor context within the current session.
   * On success, the returned accessToken is stored in TokenVault automatically.
   *
   * @contract POST /api/v1/auth/actor/switch
   * @risk MEDIUM
   * @idempotent YES
   * @sideEffects None (no DB/Redis/Queue writes)
   */
  switchActor(body: { actorId: string }, options?: RequestOptions): Promise<SwitchActorResponse>

  /**
   * Change the current user's password.
   * On success, the server evicts all sessions and blocklists all JTIs.
   * The SDK clears stored tokens automatically.
   *
   * @contract POST /api/v1/auth/password/change
   * @risk HIGH
   * @idempotent YES
   * @sideEffects DB: UPDATE credentials | Redis: evict all sessions, blocklist JTIs | Queue: outbox
   */
  changePassword(body: ChangePasswordInput, options?: RequestOptions): Promise<{ changed: true }>

  /**
   * Request a password reset OTP.
   *
   * @contract POST /api/v1/auth/password/reset/request
   * @risk COST_CRITICAL
   * @rateTier pw-reset
   * @idempotent YES — auto-generates idempotency key
   * @sideEffects Redis: SET reset OTP | Queue: otp-send
   */
  requestPasswordReset(body: PasswordResetRequestInput, options?: RequestOptions): Promise<{ requested: true }>

  /**
   * Complete password reset using OTP code.
   *
   * @contract POST /api/v1/auth/password/reset/confirm
   * @risk HIGH
   * @rateTier pw-reset-confirm
   * @idempotent YES
   * @sideEffects DB: UPDATE credentials | Redis: GETDEL reset token | Queue: outbox
   */
  confirmPasswordReset(body: PasswordResetConfirmInput, options?: RequestOptions): Promise<{ changed: true }>

  /**
   * Returns the OAuth initiation URL to redirect the browser to.
   * This is a REDIRECT endpoint — the SDK returns the URL string, NOT an HTTP response.
   * The consumer is responsible for redirecting (window.location.href or router.push).
   *
   * @contract GET /api/v1/auth/oauth/:provider → 302 Redirect
   * @risk LOW
   * @sideEffects Redis: store OAuth state token (SET)
   * @example
   *   window.location.href = client.auth.getOAuthUrl('github')
   */
  getOAuthUrl(provider: string): string

  /**
   * Handle the OAuth callback. Use in server-side or custom callback routes.
   * On success, tokens are stored in TokenVault automatically.
   *
   * @contract GET /api/v1/auth/oauth/:provider/callback?code=&state=
   * @risk AUTH_CRITICAL
   * @sideEffects DB: create/update user + identity | Redis: verify state, session creation | Queue: outbox | External: Identity Provider token exchange
   */
  handleOAuthCallback(
    provider: string,
    params: { code: string; state: string },
    options?: RequestOptions
  ): Promise<LoginResponse>
}
```

---

## ╔══ MODULE: USER CLIENT ══╗

```typescript
export class UserClient {
  /** @contract GET /api/v1/users/me | Auth: YES */
  getMe(options?: RequestOptions): Promise<unknown>
  // Returns: Profile data. Shape not specified in contract.
  // @contract Typed as unknown. Schema not defined in API contract.

  /** @contract PATCH /api/v1/users/me | Auth: YES | @contract Handler: Placeholder */
  updateMe(body: PatchUserInput, options?: RequestOptions): Promise<{ updated: true; userId: string }>

  /**
   * @contract DELETE /api/v1/users/me | Auth: YES | @contract Handler: Placeholder
   * @sideEffects DB: soft-delete | Redis: revoke all sessions
   * On success, SDK clears stored tokens.
   */
  deleteMe(options?: RequestOptions): Promise<{ deleted: true; userId: string }>

  /** @contract GET /api/v1/users/me/identities | Auth: YES */
  getIdentities(options?: RequestOptions): Promise<unknown>

  /**
   * @contract POST /api/v1/users/me/identities | Auth: YES | @contract Handler: Placeholder
   * @risk COST_CRITICAL — triggers OTP send
   * Idempotency key auto-generated.
   */
  addIdentity(body: AddIdentityInput, options?: RequestOptions): Promise<unknown>

  /** @contract DELETE /api/v1/users/me/identities/:id | Auth: YES | @contract Handler: Placeholder */
  removeIdentity(identityId: string, options?: RequestOptions): Promise<unknown>

  /** @contract GET /api/v1/users/me/audit-logs | Auth: YES */
  getAuditLogs(options?: RequestOptions): Promise<unknown>

  /**
   * @contract GET /api/v1/users/me/permissions | Auth: YES
   * @note Server resolves permissions in-memory from the JWT. No DB call.
   */
  getPermissions(options?: RequestOptions): Promise<unknown>
}
```

---

## ╔══ MODULE: SESSION CLIENT ══╗

```typescript
export class SessionClient {
  /** @contract GET /api/v1/users/me/sessions | Auth: YES */
  listSessions(options?: RequestOptions): Promise<unknown>

  /**
   * @contract DELETE /api/v1/users/me/sessions/:id | Auth: YES
   * @sideEffects Redis: HDEL session HASH, SREM from ZSET
   */
  revokeSession(sessionId: string, options?: RequestOptions): Promise<unknown>

  /** @contract GET /api/v1/users/me/devices | Auth: YES */
  listTrustedDevices(options?: RequestOptions): Promise<unknown>

  /**
   * @contract DELETE /api/v1/users/me/devices/:id | Auth: YES
   * @sideEffects Redis: SREM trusted device
   */
  removeTrustedDevice(deviceId: string, options?: RequestOptions): Promise<unknown>
}
```

---

## ╔══ MODULE: CORE CLIENT ══╗

```typescript
export class CoreClient {
  /** @contract GET /api/v1/core/me | Auth: YES */
  getIdentityContext(options?: RequestOptions): Promise<unknown>

  /** @contract GET /api/v1/core/memberships | Auth: YES */
  listMemberships(options?: RequestOptions): Promise<unknown>

  /** @contract GET /api/v1/core/actors | Auth: YES */
  listActors(options?: RequestOptions): Promise<unknown>

  /** @contract GET /api/v1/core/session | Auth: YES */
  getCurrentSession(options?: RequestOptions): Promise<unknown>

  /** @contract GET /api/v1/core/sessions | Auth: YES */
  listSessions(options?: RequestOptions): Promise<unknown>

  /**
   * @contract DELETE /api/v1/core/sessions/:sessionId | Auth: YES
   * @risk MEDIUM
   */
  revokeSession(sessionId: string, options?: RequestOptions): Promise<unknown>

  /** @contract GET /api/v1/core/auth-methods | Auth: YES */
  getAuthMethods(options?: RequestOptions): Promise<unknown>

  /** @contract GET /api/v1/core/trusted-devices | Auth: YES */
  listTrustedDevices(options?: RequestOptions): Promise<unknown>

  /**
   * @contract DELETE /api/v1/core/trusted-devices/:deviceFingerprint | Auth: YES
   * @risk MEDIUM
   */
  removeTrustedDevice(deviceFingerprint: string, options?: RequestOptions): Promise<unknown>

  /**
   * @contract PATCH /api/v1/core/profile | Auth: YES
   * @contract Handler: Placeholder on server. Fields unspecified.
   * @experimental
   */
  updateProfile(body: unknown, options?: RequestOptions): Promise<unknown>
}
```

---

## ╔══ MODULE: ADMIN CLIENT ══╗

```typescript
// All admin methods require iam:read or iam:write on the server.
// The SDK does not enforce scopes — enforcement is server-side.
// The SDK passes the stored Bearer token automatically.

export class AdminClient {
  /** @contract GET  /api/v1/admin/iam/roles          | Scope: iam:read  */
  listRoles(options?: RequestOptions): Promise<unknown>

  /** @contract POST /api/v1/admin/iam/roles          | Scope: iam:write | @risk HIGH */
  createRole(body: unknown, options?: RequestOptions): Promise<unknown>

  /** @contract DELETE /api/v1/admin/iam/roles/:id   | Scope: iam:write | @risk HIGH */
  deleteRole(roleId: string, options?: RequestOptions): Promise<unknown>

  /** @contract GET  /api/v1/admin/iam/permissions   | Scope: iam:read  */
  listPermissions(options?: RequestOptions): Promise<unknown>

  /** @contract POST /api/v1/admin/iam/permissions   | Scope: iam:write | @risk HIGH */
  createPermission(body: unknown, options?: RequestOptions): Promise<unknown>

  /** @contract DELETE /api/v1/admin/iam/permissions/:id | Scope: iam:write | @risk HIGH */
  deletePermission(permissionId: string, options?: RequestOptions): Promise<unknown>

  /** @contract GET  /api/v1/admin/iam/users/:userId/roles       | Scope: iam:read */
  getUserRoles(userId: string, options?: RequestOptions): Promise<unknown>

  /** @contract POST /api/v1/admin/iam/users/:userId/roles       | Scope: iam:write | @risk HIGH */
  assignUserRole(userId: string, body: unknown, options?: RequestOptions): Promise<unknown>

  /** @contract DELETE /api/v1/admin/iam/users/:userId/roles/:roleId | Scope: iam:write | @risk HIGH */
  removeUserRole(userId: string, roleId: string, options?: RequestOptions): Promise<unknown>

  /** @contract GET /api/v1/admin/iam/users/:userId/permissions  | Scope: iam:read */
  getUserPermissions(userId: string, options?: RequestOptions): Promise<unknown>
}
```

---

## ╔══ MODULE: PLATFORM CLIENT ══╗

```typescript
// All platform endpoints — Auth: NOT REQUIRED

export class PlatformClient {
  /** @contract GET  /api/v1/platform/manifests */
  getManifests(options?: RequestOptions): Promise<unknown>

  /** @contract GET  /api/v1/platform/openapi */
  getOpenApiSpec(options?: RequestOptions): Promise<unknown>

  /** @contract GET  /api/v1/platform/sdk-descriptor */
  getSdkDescriptor(options?: RequestOptions): Promise<unknown>

  /** @contract GET  /api/v1/platform/manifest */
  getManifest(options?: RequestOptions): Promise<unknown>

  /** @contract POST /api/v1/platform/manifest/preview */
  previewManifest(body: unknown, options?: RequestOptions): Promise<unknown>

  /** @contract POST /api/v1/platform/provider-routing/preview */
  previewProviderRouting(body: unknown, options?: RequestOptions): Promise<unknown>

  /** @contract POST /api/v1/platform/extensions/preview */
  previewExtensions(body: unknown, options?: RequestOptions): Promise<unknown>
}
```

---

## ╔══ MODULE: DYNAMIC MODULES + EXTENSIONS ══╗

```typescript
export class DynamicModuleClient {
  /** @contract GET  /api/v1/modules/:moduleKey/resources/:resourceKey | Auth: YES | @risk MEDIUM */
  getResource(moduleKey: string, resourceKey: string, options?: RequestOptions): Promise<unknown>

  /**
   * @contract POST /api/v1/modules/:moduleKey/commands/:commandKey | Auth: YES
   * @risk HIGH — arbitrary server-side execution. Validate all inputs before calling.
   * @warning The ABAC JIT layer was removed from server-side. Commands are data-driven only.
   *          Sanitize inputs externally before passing to this method.
   */
  executeCommand(moduleKey: string, commandKey: string, body: unknown, options?: RequestOptions): Promise<unknown>

  /** @contract POST /api/v1/modules/:moduleKey/actions/:actionKey | Auth: YES | @risk MEDIUM */
  executeAction(moduleKey: string, actionKey: string, body: unknown, options?: RequestOptions): Promise<unknown>
}

export class ExtensionClient {
  /**
   * @contract POST /api/v1/extensions/:extensionKey/commands/:commandKey
   * @risk HIGH — no direct guard on server (internal routing validation only)
   * @experimental Server-side guard behavior is documented as "No direct Guard".
   * @warning Validate all inputs before calling.
   */
  executeCommand(extensionKey: string, commandKey: string, body: unknown, options?: RequestOptions): Promise<unknown>

  /** @contract GET /api/v1/extensions/:extensionKey/bindings | Auth: NOT REQUIRED */
  getBindings(extensionKey: string, options?: RequestOptions): Promise<unknown>

  /** @contract GET /api/v1/extensions/:extensionKey/schema | Auth: NOT REQUIRED */
  getSchema(extensionKey: string, options?: RequestOptions): Promise<unknown>
}
```

---

## ╔══ MISSING APIs — HARD STOPS ══╗

From contract §09. These capabilities DO NOT exist on the server.
Implement stub methods that throw `UICPNotImplementedError`. Never make HTTP calls.

```typescript
// Attach these stubs to a `missing` namespace on UICPClient for discoverability.
// This helps consumers understand what is on the roadmap.

client.missing.tokenIntrospect(token: string): never
// throws UICPNotImplementedError('token_introspect', '/oauth2/introspect does not exist in the current server contract.')

client.missing.exportAuditLogs(): never
// throws UICPNotImplementedError('audit_export', 'No dedicated audit export endpoint exists. Access requires direct DB/Kafka.')

client.missing.adminRevokeDevice(userId: string, deviceId: string): never
// throws UICPNotImplementedError('admin_device_revoke', 'Admins cannot force-revoke a specific device via API. Only full account suspend is available.')

client.missing.socAlertSubscribe(): never
// throws UICPNotImplementedError('soc_alert_subscribe', 'soc-alert queue exists server-side but has no documented HTTP consumer or webhook endpoint.')
```

---

## ╔══ PACKAGE: @uicp/react ══╗

Peer deps: `react ≥ 17`, `@uicp/core`.

```typescript
// ── Provider ─────────────────────────────────────────────────────────────────

interface UICPProviderProps {
  client: UICPClient
  children: React.ReactNode
}
export function UICPProvider({ client, children }: UICPProviderProps): JSX.Element

export function useUICPClient(): UICPClient

// ── useAuth ──────────────────────────────────────────────────────────────────
// All state transitions follow the token lifecycle exactly as specified in contract.

export interface AuthState {
  isAuthenticated: boolean
  isLoading: boolean
  accessToken: string | null
  sessionId: string | null
  error: UICPError | null
}

export interface UseAuthReturn extends AuthState {
  login(body: LoginInput): Promise<LoginResponse>
  logout(): Promise<void>
  logoutAll(): Promise<void>
  sendOtp(body: SendOtpInput): Promise<{ sent: true }>
  verifyOtp(body: VerifyOtpInput): Promise<OtpVerifyResponse>
  signup(body: SignupInput): Promise<SignupResponse>
  switchActor(actorId: string): Promise<SwitchActorResponse>
  changePassword(body: ChangePasswordInput): Promise<void>
  requestPasswordReset(body: PasswordResetRequestInput): Promise<void>
  confirmPasswordReset(body: PasswordResetConfirmInput): Promise<void>
  getOAuthUrl(provider: string): string
}

export function useAuth(): UseAuthReturn

// ── useUser ───────────────────────────────────────────────────────────────────

export interface UseUserReturn {
  data: unknown
  isLoading: boolean
  error: UICPError | null
  refetch(): Promise<void>
  updateMe(body: PatchUserInput): Promise<void>
  deleteMe(): Promise<void>
}

export function useUser(): UseUserReturn

// ── useSession ────────────────────────────────────────────────────────────────

export interface UseSessionReturn {
  sessions: unknown
  trustedDevices: unknown
  isLoading: boolean
  error: UICPError | null
  refetch(): Promise<void>
  revokeSession(sessionId: string): Promise<void>
  removeTrustedDevice(deviceId: string): Promise<void>
}

export function useSession(): UseSessionReturn
```

### MockUICPProvider (for testing)

```typescript
// Testing utility — allows unit tests to inject mock response data
// without making real HTTP calls.

export interface MockHandlers {
  'auth.login'?: (body: LoginInput) => LoginResponse | UICPError
  'auth.signup'?: (body: SignupInput) => SignupResponse | UICPError
  'auth.logout'?: () => { loggedOut: true } | UICPError
  // ... one entry per SDK method
}

export function MockUICPProvider({
  children,
  handlers,
}: {
  children: React.ReactNode
  handlers?: MockHandlers
}): JSX.Element
```

---

## ╔══ PACKAGE: @uicp/testing ══╗

```typescript
// Test utilities. Zero dependency on vitest/jest — works with any test runner.

// Creates a UICPClient with MemoryAdapter and FetchAdapter replaced
// with an interceptable mock transport. Call .mock() to define responses.

export function createMockClient(config: Partial<UICPClientConfig>): {
  client: UICPClient
  mock: MockTransport
}

export class MockTransport {
  // Define what the mock transport returns for a given path
  onPost(path: string): MockRequestBuilder
  onGet(path: string): MockRequestBuilder
  onPatch(path: string): MockRequestBuilder
  onDelete(path: string): MockRequestBuilder

  // Assert call history
  assertCalled(path: string): void
  assertNotCalled(path: string): void
  assertCalledWith(path: string, body: unknown): void
  reset(): void
}

export interface MockRequestBuilder {
  reply(statusCode: number, data: unknown): void
  replyError(error: UICPError): void
}
```

---

## ╔══ STRICT GENERATION RULES ══╗

Follow every rule below without exception.

1. **Zero hallucination**: Every endpoint path, method, header, body field,
   and response shape must trace directly to a named section in this prompt.
   If it is not here, it does not exist.

2. **Placeholder handlers**: Endpoints marked `@contract Handler: Placeholder`
   must implement the HTTP call but type their response as `unknown` with the
   `@contract Placeholder` JSDoc annotation. Do NOT invent response shapes.

3. **Unknown schemas**: Any input/output schema not specified (changePasswordSchema,
   patchUserSchema, etc.) must be typed as `Record<string, unknown>` with
   the `@contract body schema = <schemaName> (server-side, fields unspecified)` JSDoc.

4. **Missing APIs**: Implement the four `.missing.*` stubs that throw
   `UICPNotImplementedError`. No HTTP calls, no invented endpoints.

5. **No retry on non-idempotent**: `POST /auth/refresh`, `POST /auth/otp/send`,
   `POST /auth/otp/verify` must NEVER be retried on network failure.

6. **Token clearing**: On success of `logout`, `logoutAll`, `deleteMe`,
   `changePassword`: always call `vault.clearTokens()` and emit `tokens:cleared`.

7. **Token storage on success**: On success of `login`, `handleOAuthCallback`,
   `switchActor`: always call `vault.setTokens()` and emit `tokens:set`.

8. **No framework lock-in in @uicp/core**: Zero import of React, Vue, Angular,
   or any browser globals. Detect `globalThis.localStorage` at runtime inside
   `LocalStorageAdapter`, throw a descriptive error if missing.

9. **sideEffects: false** in every package.json. Full tree-shaking must work.

10. **TypeScript strict mode**: `"strict": true` in every tsconfig.
    No `any` except where explicitly typed as `unknown` per this prompt.

11. **Named exports only**: No default exports. Every export is named.

12. **JSDoc on every public method**: Method signature, @contract path,
    @risk level, @rateTier if applicable, @sideEffects, @warning if applicable.

---

## ╔══ DELIVERY CHECKLIST ══╗

Before completing generation, verify:

- [ ] `UICPClient.create()` and `UICPClient.builder()` both work
- [ ] All 8 sub-clients are accessible as properties
- [ ] All 14 auth endpoints match the contract exactly
- [ ] Token vault auto-clears on logout/changePassword/deleteMe
- [ ] Token vault auto-stores on login/oauth/switchActor
- [ ] `POST /auth/refresh` has NO retry logic
- [ ] All 4 COST CRITICAL endpoints auto-generate idempotency keys
- [ ] All 4 missing APIs throw `UICPNotImplementedError` with descriptive messages
- [ ] `@uicp/react` has `UICPProvider`, `useAuth`, `useUser`, `useSession`
- [ ] `@uicp/testing` has `createMockClient` and `MockTransport`
- [ ] `@uicp/types` has zero runtime code (types only)
- [ ] All packages have `sideEffects: false` in package.json
- [ ] ESM + CJS dual output via tsup
- [ ] TypeScript strict mode across all packages
- [ ] Zero `any` types outside explicitly `unknown`-typed placeholders
```
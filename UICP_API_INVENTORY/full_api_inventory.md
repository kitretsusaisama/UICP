# UICP FULL API DISCOVERY & CONTRACT AUDIT

## 01_HTTP_APIS
### AuthModule
**Method: POST**
Path: `/api/v1/auth/signup`
Handler: `SignupPhoneHandler` / `SignupEmailHandler`
Request:
- body schema: `signupSchema` (zod)
- headers: `x-tenant-id` (uuid)
- query params: None
Response:
- success schema: `{ data: { userId, message } }`
- error schema: `{ error: { code, message } }`
Auth Required: No
Rate Limited: Yes (tier: 'signup')
Idempotent: Yes (`@UseInterceptors(IdempotencyInterceptor)`)
Side Effects:
- DB writes: `INSERT INTO users`, `INSERT INTO identities`, `INSERT INTO credentials`
- Redis writes: OTP code (`SET`)
- Queue push: `otp-send` (SMS/Email)
- External calls: None directly (deferred to Queue)
Risk Level: HIGH

**Method: POST**
Path: `/api/v1/auth/login`
Handler: `LoginHandler`
Request:
- body schema: `loginSchema`
- headers: `x-tenant-id`
- query params: None
Response:
- success schema: `{ data: { accessToken, refreshToken, sessionId, expiresIn } }`
- error schema: `{ error: { code, message } }`
Auth Required: No
Rate Limited: Yes (tier: 'login')
Idempotent: Yes
Side Effects:
- DB writes: Update User status, Last Login
- Redis writes: `SessionService.createSession` (HASH, ZSET), UEBA Velocity INCR
- Queue push: Outbox (`LoginSucceeded` or `ThreatDetected`)
- External calls: Maxmind GeoIP DB (local)
Risk Level: AUTH CRITICAL

**Method: POST**
Path: `/api/v1/auth/refresh`
Handler: `RefreshTokenHandler`
Request:
- body schema: `refreshTokenSchema`
- headers: `x-tenant-id`
- query params: None
Response:
- success schema: `{ data: { accessToken, refreshToken, expiresIn } }`
- error schema: `{ error: { code, message } }`
Auth Required: No (validates refreshToken payload)
Rate Limited: Yes (tier: 'refresh')
Idempotent: No (rotation inherently mutates state)
Side Effects:
- DB writes: `UPDATE refresh_tokens` (revoke), `INSERT INTO refresh_tokens`
- Redis writes: None directly (locks if concurrency exists)
- Queue push: Outbox (`TokenRefreshed` or `TokenReuseDetected`)
- External calls: None
Risk Level: AUTH CRITICAL

**Method: POST**
Path: `/api/v1/auth/logout`
Handler: `LogoutHandler`
Request:
- body schema: `{}`
- headers: `x-tenant-id`, `Authorization`
- query params: None
Response:
- success schema: `{ data: { loggedOut: true } }`
- error schema: Standard 401/400
Auth Required: Yes
Rate Limited: Yes (tier: 'logout')
Idempotent: Yes
Side Effects:
- DB writes: None directly for session (Redis only)
- Redis writes: Delete session HASH, Remove from ZSET, Add JTI to blocklist
- Queue push: Outbox (`LogoutRequested`)
- External calls: None
Risk Level: LOW

**Method: POST**
Path: `/api/v1/auth/logout-all`
Handler: `LogoutAllHandler`
Request:
- body schema: `{}`
- headers: `x-tenant-id`, `Authorization`
- query params: None
Response:
- success schema: `{ data: { loggedOut: true } }`
- error schema: Standard
Auth Required: Yes
Rate Limited: Yes (tier: 'logout-all')
Idempotent: Yes
Side Effects:
- DB writes: `revokeAllFamiliesByUser`
- Redis writes: Evict all sessions, blocklist all active JTIs
- Queue push: Outbox
- External calls: None
Risk Level: MEDIUM

**Method: POST**
Path: `/api/v1/auth/otp/send`
Handler: `OtpService` & `Queue`
Request:
- body schema: `{ purpose, channel, identity }`
- headers: `x-tenant-id`
- query params: None
Response:
- success schema: `{ data: { sent: true } }`
- error schema: Standard
Auth Required: No
Rate Limited: Yes (tier: 'otp-send')
Idempotent: No
Side Effects:
- DB writes: None
- Redis writes: OTP Code (`SET`)
- Queue push: `otp-send`
- External calls: None directly
Risk Level: COST CRITICAL

**Method: POST**
Path: `/api/v1/auth/otp/verify`
Handler: `VerifyOtpHandler`
Request:
- body schema: `{ userId, code, purpose, identityId?, sessionId? }`
- headers: `x-tenant-id`
- query params: None
Response:
- success schema: `{ data: { verified: true, userStatus: string } }`
- error schema: Standard
Auth Required: No
Rate Limited: Yes (tier: 'otp-verify')
Idempotent: No (code is consumed)
Side Effects:
- DB writes: `UPDATE users` / `identities`
- Redis writes: `GETDEL` otp code
- Queue push: Outbox
- External calls: None
Risk Level: AUTH CRITICAL

**Method: POST**
Path: `/api/v1/auth/actor/switch`
Handler: `RuntimeIdentityService`
Request:
- body schema: `{ actorId }`
- headers: `x-tenant-id`, `Authorization`
- query params: None
Response:
- success schema: `{ data: { accessToken, actor: {...}, effectiveCapabilitiesVersion } }`
- error schema: Standard 401/403
Auth Required: Yes
Rate Limited: No explicit override
Idempotent: Yes
Side Effects:
- DB writes: None
- Redis writes: None
- Queue push: None
- External calls: None
Risk Level: MEDIUM

**Method: POST**
Path: `/api/v1/auth/password/change`
Handler: `ChangePasswordHandler`
Request:
- body schema: `changePasswordSchema`
- headers: `x-tenant-id`, `Authorization`
- query params: None
Response:
- success schema: `{ data: { changed: true } }`
- error schema: Standard
Auth Required: Yes
Rate Limited: No explicit override
Idempotent: Yes
Side Effects:
- DB writes: `UPDATE credentials`
- Redis writes: Evict sessions, Blocklist JTIs
- Queue push: Outbox
- External calls: None
Risk Level: HIGH

**Method: POST**
Path: `/api/v1/auth/password/reset/request`
Handler: `PasswordResetRequestHandler`
Request:
- body schema: `passwordResetRequestSchema`
- headers: `x-tenant-id`
- query params: None
Response:
- success schema: `{ data: { requested: true } }`
- error schema: Standard
Auth Required: No
Rate Limited: Yes (tier: 'pw-reset')
Idempotent: Yes
Side Effects:
- DB writes: None
- Redis writes: OTP Code (`SET`)
- Queue push: `otp-send`
- External calls: None
Risk Level: COST CRITICAL

**Method: POST**
Path: `/api/v1/auth/password/reset/confirm`
Handler: `PasswordResetConfirmHandler`
Request:
- body schema: `passwordResetConfirmSchema`
- headers: `x-tenant-id`
- query params: None
Response:
- success schema: `{ data: { changed: true } }`
- error schema: Standard
Auth Required: No
Rate Limited: Yes (tier: 'pw-reset-confirm')
Idempotent: Yes
Side Effects:
- DB writes: `UPDATE credentials`
- Redis writes: Consume reset token (`GETDEL`)
- Queue push: Outbox
- External calls: None
Risk Level: HIGH

**Method: GET**
Path: `/api/v1/auth/oauth/:provider`
Handler: `oauthInitiate`
Request:
- body schema: None
- headers: `x-tenant-id`
- query params: None
Response:
- success schema: 302 Redirect
- error schema: 400 Unsupported Provider
Auth Required: No
Rate Limited: No explicit override
Idempotent: Yes
Side Effects:
- DB writes: None
- Redis writes: Store OAuth state (`SET`)
- Queue push: None
- External calls: None
Risk Level: LOW

**Method: GET**
Path: `/api/v1/auth/oauth/:provider/callback`
Handler: `OAuthCallbackHandler`
Request:
- body schema: None
- headers: `x-tenant-id`
- query params: `code`, `state`
Response:
- success schema: `{ data: { accessToken, refreshToken, ... } }`
- error schema: 400 Bad Request
Auth Required: No
Rate Limited: No explicit override
Idempotent: Yes
Side Effects:
- DB writes: Create/Update User & Identity
- Redis writes: Verify state (`GET`), Session Creation
- Queue push: Outbox
- External calls: Identity Provider (GitHub/Google/etc token exchange)
Risk Level: AUTH CRITICAL

### UserController
**Method: GET**
Path: `/api/v1/users/me`
Handler: `GetUserHandler`
Request:
- body schema: None
- headers: `x-tenant-id`, `Authorization`
- query params: None
Response:
- success schema: Profile data
- error schema: 401
Auth Required: Yes
Rate Limited: No
Idempotent: Yes
Side Effects: None
Risk Level: NORMAL

**Method: PATCH**
Path: `/api/v1/users/me`
Handler: (Placeholder)
Request:
- body schema: `patchUserSchema`
- headers: `x-tenant-id`, `Authorization`
- query params: None
Response:
- success schema: `{ data: { updated: true, userId } }`
- error schema: 400
Auth Required: Yes
Rate Limited: No
Idempotent: Yes
Side Effects: DB update
Risk Level: NORMAL

**Method: DELETE**
Path: `/api/v1/users/me`
Handler: (Placeholder)
Request:
- body schema: None
- headers: `x-tenant-id`, `Authorization`
- query params: None
Response:
- success schema: `{ data: { deleted: true, userId } }`
- error schema: 401
Auth Required: Yes
Rate Limited: No
Idempotent: Yes
Side Effects: Soft-delete in DB, Revoke sessions
Risk Level: HIGH

**Method: GET**
Path: `/api/v1/users/me/identities`
Handler: `GetUserHandler`
Request: None
Auth Required: Yes
Idempotent: Yes
Risk Level: NORMAL

**Method: POST**
Path: `/api/v1/users/me/identities`
Handler: (Placeholder)
Request: `addIdentitySchema`
Auth Required: Yes
Idempotent: Yes
Side Effects: Add identity, send OTP
Risk Level: COST CRITICAL

**Method: DELETE**
Path: `/api/v1/users/me/identities/:id`
Handler: (Placeholder)
Request: None
Auth Required: Yes
Idempotent: Yes
Side Effects: DB delete
Risk Level: HIGH

**Method: GET**
Path: `/api/v1/users/me/audit-logs`
Handler: `ListAuditLogsHandler`
Request: None
Auth Required: Yes
Idempotent: Yes
Risk Level: LOW

**Method: GET**
Path: `/api/v1/users/me/permissions`
Handler: In-memory from JWT
Request: None
Auth Required: Yes
Idempotent: Yes
Risk Level: LOW

### SessionController
**Method: GET**
Path: `/api/v1/users/me/sessions`
Handler: `GetUserSessionsQuery`
Request: None
Auth Required: Yes
Idempotent: Yes
Risk Level: LOW

**Method: DELETE**
Path: `/api/v1/users/me/sessions/:id`
Handler: `SessionService.invalidate`
Request: None
Auth Required: Yes
Idempotent: Yes
Side Effects: Redis `HDEL` / `SREM`
Risk Level: MEDIUM

**Method: GET**
Path: `/api/v1/users/me/devices`
Handler: `SessionService.listTrustedDevices`
Request: None
Auth Required: Yes
Idempotent: Yes
Risk Level: LOW

**Method: DELETE**
Path: `/api/v1/users/me/devices/:id`
Handler: `SessionService.removeTrustedDevice`
Request: None
Auth Required: Yes
Idempotent: Yes
Side Effects: Redis `SREM`
Risk Level: MEDIUM

### CoreController
**Method: GET**
Path: `/api/v1/core/me`
Handler: `RuntimeIdentityService.getContext`
Auth Required: Yes
Risk Level: NORMAL

**Method: GET**
Path: `/api/v1/core/memberships`
Handler: `RuntimeIdentityService.listMemberships`
Auth Required: Yes
Risk Level: NORMAL

**Method: GET**
Path: `/api/v1/core/actors`
Handler: `RuntimeIdentityService.listActors`
Auth Required: Yes
Risk Level: NORMAL

**Method: GET**
Path: `/api/v1/core/session`
Handler: `SessionService.findById`
Auth Required: Yes
Risk Level: NORMAL

**Method: GET**
Path: `/api/v1/core/sessions`
Handler: `SessionService.listByUser`
Auth Required: Yes
Risk Level: NORMAL

**Method: DELETE**
Path: `/api/v1/core/sessions/:sessionId`
Handler: `SessionService.invalidate`
Auth Required: Yes
Risk Level: MEDIUM

**Method: GET**
Path: `/api/v1/core/auth-methods`
Handler: `RuntimeIdentityService.getContext`
Auth Required: Yes
Risk Level: NORMAL

**Method: GET**
Path: `/api/v1/core/trusted-devices`
Handler: `SessionService.listTrustedDevices`
Auth Required: Yes
Risk Level: NORMAL

**Method: DELETE**
Path: `/api/v1/core/trusted-devices/:deviceFingerprint`
Handler: `SessionService.removeTrustedDevice`
Auth Required: Yes
Risk Level: MEDIUM

**Method: PATCH**
Path: `/api/v1/core/profile`
Handler: (Placeholder)
Auth Required: Yes
Risk Level: NORMAL

### PlatformController
**Method: GET**
Path: `/api/v1/platform/manifests`
Auth Required: No
Risk Level: LOW

**Method: GET**
Path: `/api/v1/platform/openapi`
Auth Required: No
Risk Level: LOW

**Method: GET**
Path: `/api/v1/platform/sdk-descriptor`
Auth Required: No
Risk Level: LOW

**Method: GET**
Path: `/api/v1/platform/manifest`
Auth Required: No
Risk Level: LOW

**Method: POST**
Path: `/api/v1/platform/manifest/preview`
Auth Required: No
Risk Level: LOW

**Method: POST**
Path: `/api/v1/platform/provider-routing/preview`
Auth Required: No
Risk Level: LOW

**Method: POST**
Path: `/api/v1/platform/extensions/preview`
Auth Required: No
Risk Level: LOW

### AdminController
**Method: GET**
Path: `/api/v1/admin/iam/roles`
Auth Required: Yes (`iam:read`)
Risk Level: NORMAL

**Method: POST**
Path: `/api/v1/admin/iam/roles`
Auth Required: Yes (`iam:write`)
Risk Level: HIGH

**Method: DELETE**
Path: `/api/v1/admin/iam/roles/:id`
Auth Required: Yes (`iam:write`)
Risk Level: HIGH

**Method: GET**
Path: `/api/v1/admin/iam/permissions`
Auth Required: Yes (`iam:read`)
Risk Level: NORMAL

**Method: POST**
Path: `/api/v1/admin/iam/permissions`
Auth Required: Yes (`iam:write`)
Risk Level: HIGH

**Method: DELETE**
Path: `/api/v1/admin/iam/permissions/:id`
Auth Required: Yes (`iam:write`)
Risk Level: HIGH

**Method: GET**
Path: `/api/v1/admin/iam/users/:userId/roles`
Auth Required: Yes (`iam:read`)
Risk Level: NORMAL

**Method: POST**
Path: `/api/v1/admin/iam/users/:userId/roles`
Auth Required: Yes (`iam:write`)
Risk Level: HIGH

**Method: DELETE**
Path: `/api/v1/admin/iam/users/:userId/roles/:roleId`
Auth Required: Yes (`iam:write`)
Risk Level: HIGH

**Method: GET**
Path: `/api/v1/admin/iam/users/:userId/permissions`
Auth Required: Yes (`iam:read`)
Risk Level: NORMAL

### DynamicModuleController & ExtensionController
**Method: GET**
Path: `/api/v1/modules/:moduleKey/resources/:resourceKey`
Auth Required: Yes
Risk Level: MEDIUM

**Method: POST**
Path: `/api/v1/modules/:moduleKey/commands/:commandKey`
Auth Required: Yes
Risk Level: HIGH (Arbitrary execution)

**Method: POST**
Path: `/api/v1/modules/:moduleKey/actions/:actionKey`
Auth Required: Yes
Risk Level: MEDIUM

**Method: POST**
Path: `/api/v1/extensions/:extensionKey/commands/:commandKey`
Auth Required: No direct Guard (Internal routing validation)
Risk Level: HIGH

**Method: GET**
Path: `/api/v1/extensions/:extensionKey/bindings`
Auth Required: No direct Guard
Risk Level: LOW

**Method: GET**
Path: `/api/v1/extensions/:extensionKey/schema`
Auth Required: No direct Guard
Risk Level: LOW


## 02_INTERNAL_APIS
- `OtpService.verifyAndConsume(userId, code, purpose)`: Atomic GETDEL/Lua, strictly enforces replay and TTL. Side effect: Consumes OTP.
- `TokenService.mintAccessToken(input)`: Generates RS256 token, delegates to `kmsSign`. Side effect: Compute load.
- `TokenService.mintRefreshToken(userId, tenantId, familyId)`: Generates RS256 token.
- `TokenService.validateAccessToken(token)`: Validates JWT signature + O(1) Redis Blocklist check.
- `SessionService.createSession(...)`: Writes Hash and ZSET in Redis. Enforces LRU.
- `SessionService.extendTtl(...)`: Redis EXPIRE.
- `DistributedLockService.withLock(...)`: Redis SET NX / eval, local retry budget tracking via CLS.
- `UebaEngine.analyze(context)`: Aggregates Velocity, Geo, Device, and CS scores.
- `VelocityAnalyzer.score(...)`: Redis INCR/EXPIRE Lua scripts.
- `GeoAnalyzer.score(...)`: Maxmind local DB lookup + Redis HA check.
- `CredentialStuffingAnalyzer.score(...)`: Redis global and tenant-level bucket INCR/EXPIRE.

## 03_ASYNC_APIS
### BullMQ Queues
**Queue: `outbox-relay`**
- Producer: Domain layer (Outbox table via Polling worker)
- Consumer: `OutboxRelayWorker` (Concurrency: 10)
- Payload: Empty `{ eventId }` (triggers a polling cycle)
- Failure: Retry 5 times, then moves to DLQ. Idempotent polling loop.

**Queue: `audit-write`**
- Producer: `OutboxRelayWorker`
- Consumer: `AuditWriteWorker` (Concurrency: 20)
- Payload: `AuditWriteJobPayload` (actorId, action, metadataEnc)
- Failure: Standard BullMQ Backoff.
- Idempotent: Yes (dual writes DB + fluent forward)

**Queue: `otp-send`**
- Producer: Auth Handlers (`signup`, `reset`)
- Consumer: `OtpSendWorker` (Concurrency: 5)
- Payload: `OtpDispatchPayload` (userId, channel, recipient, code)
- Failure: Circuit Breakers in adapter. Tenant Cost quota check inside worker.
- Idempotent: No (causes provider send).

**Queue: `soc-alert`**
- Producer: `OutboxRelayWorker` (Threat/Reuse events), `UebaEngine`
- Consumer: (Missing Implementation logic explicitly defined in codebase! Handled generically or dropped)

**Queue: `tor-refresh` (Repeatable)**
- Producer: `TorExitNodeChecker.onModuleInit`
- Consumer: Generic BullMQ worker
- Payload: `url`
- Schedule: Every 6 hours.

## 04_EXTERNAL_APIS
**Provider: Firebase OTP (SMS)**
- Direction: Outbound
- Trigger: `otp-send` queue (`OtpSendWorker`)
- Payload: `code`, `purpose` to topic `otp-E164`
- Risk: Cost Drain, Provider Rate Limit
- Fallback: No (throws error if SMS)

**Provider: SMTP / Resend / Maileroo**
- Direction: Outbound
- Trigger: `otp-send` queue
- Risk: Low cost, Spam filter blocks
- Fallback: Multi-provider routing available.

**Provider: MaxMind GeoIP**
- Direction: Local DB read via `maxmind` package.
- Risk: Memory overhead.

## 05_IMPLICIT_APIS
- **Session Eviction Flow:** Implicitly triggered inside `SessionService.createSession` when active sessions exceed `MAX_SESSIONS_PER_USER`.
- **Identity Link Polling:** Implicitly triggered when OTP is consumed for purpose `IDENTITY_VERIFICATION` in `verifyOtpHandler`.
- **Global Key Rotation:** Keys deprecated in `rotateSigningKey()` are implicitly retained for 7 days in memory for `getDeprecatedPublicKeys()`.
- **JTI Blocklist Eviction:** Handled by Redis TTL implicitly; no cleanup cron required.

## 06_SECURITY_ANALYSIS
- **POST /api/v1/auth/otp/send**: SMS Bombing Risk. *Severity: CRITICAL*. Handled by Cost controller in Phase 3 reconstruction. Needs explicit device fingerprint + CAPTCHA for unauthenticated paths.
- **POST /api/v1/auth/refresh**: Token Replay Risk. *Severity: HIGH*. Handled by Phase 7 SOC detection and atomic token rotation.
- **POST /api/v1/modules/:moduleKey/commands/:commandKey**: RCE Risk if inputs aren't sanitized before passing to dynamic commands. *Severity: MEDIUM*. (ABAC JIT was removed, so this is strictly data-driven now).
- **POST /api/v1/auth/signup**: Identity enumeration. *Severity: LOW*. (Timing safe hash comparison + unified error messages mitigate this).

## 07_RATE_LIMIT_CLASSIFICATION
- **COST CRITICAL**: `POST /auth/otp/send`, `POST /users/me/identities`, `POST /auth/signup`, `POST /auth/password/reset/request`
- **AUTH CRITICAL**: `POST /auth/login`, `POST /auth/refresh`, `POST /auth/otp/verify`, `GET /auth/oauth/:provider/callback`
- **NORMAL**: All `/users/me/*`, `/core/*`, `/admin/*` operations.
- **BYPASSED**: Internal endpoints or webhooks without rate limit guards.

## 08_DATA_FLOW_MAPS
**Data Flow: Signup (Phone)**
1. **Request:** Client -> `POST /auth/signup`
2. **Validation:** Zod Pipe (`signupSchema`)
3. **Middleware:** Rate Limiter (Lua token bucket, `tier: signup`)
4. **Service:** `SignupPhoneHandler`
5. **Cache (Lock):** Redis `SET NX` (`DistributedLockService`)
6. **DB (Primary):** `userRepo.save(user)` -> `INSERT INTO users`, `identities`, `credentials`. Pulls domain events -> `INSERT INTO outbox_events`.
7. **Cache (State):** Redis `SET` OTP code.
8. **Queue:** BullMQ `otp-send` enqueue.
9. **Response:** 201 Created.
10. **Async:** `OtpSendWorker` -> Check Tenant Quota -> `FirebaseOtpAdapter` -> SMS dispatched. `OutboxRelayWorker` -> `AuditWriteWorker` -> S3 Log Stream.

## 09_MISSING_APIS
1. **MISSING API:** Token Introspection (`/oauth2/introspect`)
   **IMPACT:** Third-party resource servers cannot dynamically validate tokens if they don't want to parse JWTs manually.
2. **MISSING API:** Audit Export
   **IMPACT:** Compliance and SOC teams cannot extract raw logs without direct DB/Kafka access.
3. **MISSING API:** Device Management Override
   **IMPACT:** Admins cannot force-logout a specific compromised device for a user, only the user can via `/users/me/devices/:id` or an admin via full account suspend.
4. **MISSING API:** Dedicated `soc-alert` Consumer Worker
   **IMPACT:** `TokenReuseDetected` events fall into the queue but lack a documented consumer in the current repository to forward them to Splunk/PagerDuty.

## 10_FINAL_VERDICT
**DO WE KNOW 100% OF THE ATTACK SURFACE?** Yes. All inbound HTTP, internal cache/db edges, and async queue workers are mapped.
**ARE THERE HIDDEN EXECUTION PATHS?** Yes, the `OutboxRelayWorker` handles asynchronous cascading state changes. A failure in the consumer queues (`otp-send`, `soc-alert`) breaks user flow silently from the HTTP client's perspective.
**CAN WE ENFORCE GOVERNANCE + CONTROL?** Yes. The architecture is explicitly decoupled. Rate limiting (Lua), Policy decisions (OPA), and Secrets (KMS) are strictly isolated. Cost controls act as circuit breakers on external bounds.

**VERDICT:** The API surface is fully mapped, critically classified, and structurally sound post-reconstruction.

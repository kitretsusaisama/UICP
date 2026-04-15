# Implementation Plan: Unified Identity Control Plane (UICP) — Enterprise Edition v2

## Overview

This plan implements the UICP as a production-grade NestJS service using Hexagonal Architecture, CQRS, Event Sourcing, and the Transactional Outbox Pattern. Tasks are ordered by dependency: domain layer first (zero framework imports), then ports, then infrastructure adapters, then application use cases, then interface layer, then cross-cutting concerns (resilience, security, observability), and finally deployment artifacts.

TypeScript is used throughout. All tasks reference the requirements they satisfy.

---

## Tasks

### Phase 1: Project Foundation

- [x] 1. Bootstrap NestJS project with TypeScript, module structure, and shared infrastructure
  - Initialize NestJS project with strict TypeScript config (`strict: true`, `noUncheckedIndexedAccess: true`)
  - Configure `tsconfig.json` with path aliases (`@domain/*`, `@application/*`, `@infrastructure/*`, `@interface/*`, `@shared/*`)
  - Install core dependencies: `@nestjs/core`, `@nestjs/common`, `@nestjs/config`, `nestjs-cls`, `zod`, `pino`, `pino-http`, `fast-check`, `jest`, `@types/node`
  - Create `src/app.module.ts` as root module importing `ConfigModule.forRoot({ isGlobal: true })` and `ClsModule.forRoot({ global: true })`
  - Create `src/main.ts` with bootstrap function, Pino logger, and graceful shutdown hooks (SIGTERM/SIGINT with 25s drain window)
  - Create `src/shared/config/config.module.ts` with Zod-validated environment schema (DB, Redis, JWT, encryption, OTP env vars)
  - Create `src/shared/cls/cls.module.ts` exporting `ClsService` with typed store interface (`requestId`, `tenantId`, `userId`, `traceId`, `sessionId`)
  - Create `src/shared/utils/timing-safe-equal.ts` using `crypto.timingSafeEqual`
  - Create `src/shared/utils/haversine.ts` implementing great-circle distance formula
  - _Implements: Req 1, Req 2, Req 3_

  - [x] 1.1 Write unit tests for timing-safe-equal and haversine utilities
    - Test `timingSafeEqual` with equal and unequal strings of same length
    - Test `haversine` with known city-pair distances (e.g., NYC→London ≈ 5570 km)
    - _Implements: Req 3.8, Req 11.3_


### Phase 2: Domain Layer

- [x] 2. Implement Value Objects
  - Create `src/domain/exceptions/domain.exception.ts` with `DomainException` base class carrying `errorCode` and `message`
  - Create `src/domain/exceptions/domain-error-codes.ts` enumerating all error codes from the Invariant Violation Matrix (Section 3.8)
  - Create `src/domain/value-objects/tenant-id.vo.ts`: UUID v4 validation, `create()`, `from()`, `fromOptional()`, `equals()`, `toString()`
  - Create `src/domain/value-objects/user-id.vo.ts`, `identity-id.vo.ts`, `session-id.vo.ts`, `token-id.vo.ts` — same pattern as TenantId
  - Create `src/domain/value-objects/email.vo.ts`: RFC 5322 regex, max 320 chars, lowercase+trim, disposable-domain blocklist (10K+ domains), `getValue()`, `getDomain()`, `toHmacInput()`
  - Create `src/domain/value-objects/phone-number.vo.ts`: E.164 format, 8–15 digits after `+`, `getValue()`, `getCountryCode()`
  - Create `src/domain/value-objects/raw-password.vo.ts`: min 10 / max 128 chars, uppercase, lowercase, digit, special char, top-10K common passwords blocklist, `getValue()`
  - Create `src/domain/value-objects/abac-condition.vo.ts`: DSL parser producing AST, `parse()`, `evaluate(context)`, `toJSON()`
  - _Implements: Req 2.4, Req 2.5, Req 2.6, Req 9.1, Req 9.2_

  - [x] 2.1 Write property test for Email value object (Property 7 — roundtrip via HMAC input)
    - **Property 7 (partial): Email.create(valid) always produces a normalized lowercase value**
    - **Validates: Req 2.4**
    - Use `fc.emailAddress()` filtered to non-disposable domains; assert `email.getValue()` equals lowercased input

  - [x] 2.2 Write unit tests for all value object invariants
    - Email: invalid RFC format, disposable domain, >320 chars each throw `INVALID_EMAIL`
    - PhoneNumber: non-E.164 inputs throw `INVALID_PHONE_NUMBER`
    - RawPassword: each failing rule (length, uppercase, lowercase, digit, special, common) throws `WEAK_PASSWORD`
    - TenantId/UserId/etc.: non-UUID inputs throw `INVALID_TENANT_ID` / `INVALID_USER_ID`
    - _Implements: Req 2.4, Req 2.5, Req 2.6_

- [x] 3. Implement Domain Entities and Aggregates
  - Create `src/domain/entities/identity.entity.ts`: `Identity` class with `createEmail()`, `createPhone()`, `createOAuth()` factories; `verify()`, `updateProviderData()`, `isVerified()`, `getValueHash()`, `getType()`; throws `IDENTITY_ALREADY_VERIFIED` on double-verify
  - Create `src/domain/entities/credential.entity.ts`: `Credential` entity holding hash, algorithm, rounds, `needsRehash()` method
  - Create `src/domain/entities/device.entity.ts`: `Device` entity with fingerprint, trusted flag, `trust()` method
  - Create `src/domain/aggregates/user.aggregate.ts`: full `User` aggregate with state machine (PENDING→ACTIVE→SUSPENDED→DELETED), `createWithEmail()`, `createWithPhone()`, `fromEvents()`, `activate()`, `suspend()`, `unsuspend()`, `delete()`, `linkIdentity()`, `verifyIdentity()`, `changePassword()`, `pullDomainEvents()`; all invariants from Section 3.3
  - Create `src/domain/aggregates/session.aggregate.ts`: `Session` aggregate with state machine (CREATED→MFA_PENDING→ACTIVE→EXPIRED/REVOKED), `create()`, `requireMfa()`, `verifyMfa()`, `revoke()`, `isExpired()`, `isActive()`, `extendTtl()`
  - _Implements: Req 1, Req 2.1, Req 2.2, Req 3, Req 6.6, Req 6.7, Req 8_

  - [x] 3.1 Write property test for User aggregate state machine (Property 1 — state transitions)
    - **Property 1: User state machine never reaches an invalid transition**
    - **Validates: Req 3.5, Req 3.6, Req 3.7**
    - Generate arbitrary sequences of valid commands; assert state is always one of {PENDING, ACTIVE, SUSPENDED, DELETED} and DELETED is terminal

  - [x] 3.2 Write property test for User.fromEvents round-trip (Property 18 — event ordering)
    - **Property 18: Events replayed in aggregate_seq order always reconstruct the same aggregate state**
    - **Validates: Req 2.1, Req 6.6**
    - Generate arbitrary valid event sequences; assert `fromEvents(events).getStatus()` matches expected final state

  - [x] 3.3 Write unit tests for User aggregate invariants
    - `activate()` without verified identity throws `CANNOT_ACTIVATE_WITHOUT_VERIFIED_IDENTITY`
    - `activate()` when not PENDING throws `INVALID_STATUS_TRANSITION`
    - `suspend()` when not ACTIVE throws `INVALID_STATUS_TRANSITION`
    - `delete()` when already DELETED throws `INVALID_STATUS_TRANSITION`
    - `linkIdentity()` with ≥3 of same type throws `MAX_IDENTITIES_PER_TYPE_EXCEEDED`
    - `linkIdentity()` with duplicate valueHash throws `IDENTITY_ALREADY_LINKED`
    - `verifyIdentity()` with unknown id throws `IDENTITY_NOT_FOUND`
    - _Implements: Req 2, Req 3_

- [x] 4. Implement Domain Events and Domain Services
  - Create all 14 domain event types in `src/domain/events/` (Section 3.7): `UserCreatedEvent`, `UserActivatedEvent`, `UserSuspendedEvent`, `UserUnsuspendedEvent`, `UserDeletedEvent`, `IdentityLinkedEvent`, `IdentityVerifiedEvent`, `SessionCreatedEvent`, `SessionRevokedEvent`, `LoginSucceededEvent`, `LoginFailedEvent`, `TokenRefreshedEvent`, `TokenReuseDetectedEvent`, `OtpVerifiedEvent`, `PasswordChangedEvent`, `ThreatDetectedEvent`
  - Create `src/domain/services/auth-policy.domain-service.ts`: `AuthPolicyDomainService.evaluate()` implementing the 6-step check chain (DELETED→SUSPENDED→PENDING→MFA_required→MFA_adaptive→ALLOW)
  - Create `src/domain/services/abac-policy.domain-service.ts`: `AbacPolicyDomainService` with `evaluate(policies, context)` implementing deny-override algorithm (Section 3.6)
  - _Implements: Req 3.1–3.7, Req 9.3–9.6_

  - [x] 4.1 Write unit tests for AuthPolicyDomainService
    - DELETED user → DENY(ACCOUNT_DELETED)
    - SUSPENDED user with future `suspendUntil` → DENY(ACCOUNT_SUSPENDED) with retryAfter
    - PENDING user → DENY(ACCOUNT_NOT_ACTIVATED)
    - MFA policy `required` → REQUIRE_MFA regardless of threat score
    - MFA policy `adaptive` + score > 0.35 → REQUIRE_MFA
    - All checks pass → ALLOW
    - _Implements: Req 3.5, Req 3.6, Req 3.7_

  - [x] 4.2 Write property test for ABAC deny-override (Property 11)
    - **Property 11: Any matching DENY policy overrides all ALLOW policies regardless of priority**
    - **Validates: Req 9.3**
    - Generate arbitrary policy sets with at least one matching DENY; assert decision is always DENY


### Phase 3: Port Interfaces and Injection Tokens

- [x] 5. Define all port interfaces and injection tokens
  - Create `src/application/ports/injection-tokens.ts` with all 15 `Symbol` constants from Section 4.1
  - Create `src/application/ports/driven/i-user.repository.ts`: `IUserRepository` with `findById()`, `findByTenantId()`, `save()`, `update()` — all methods require `TenantId` parameter
  - Create `src/application/ports/driven/i-identity.repository.ts`: `IIdentityRepository` with `findByHash()`, `findByUserId()`, `findByProviderSub()`, `save()`, `verify()` (Section 4.2)
  - Create `src/application/ports/driven/i-session.store.ts`: `ISessionStore` with `create()`, `findById()`, `findByUserId()`, `invalidate()`, `invalidateAll()`, `extendTtl()`, `setStatus()`
  - Create `src/application/ports/driven/i-token.repository.ts`: `ITokenRepository` with `saveRefreshToken()`, `findRefreshToken()`, `revokeToken()`, `revokeFamily()`, `revokeAllFamiliesByUser()`, `isBlocklisted()`, `addToBlocklist()`, `getActiveJtisByUser()`
  - Create `src/application/ports/driven/i-event-store.ts`: `IEventStore` with `append()`, `loadEvents()` — `append()` throws on duplicate `aggregateSeq`
  - Create `src/application/ports/driven/i-outbox.repository.ts`: `IOutboxRepository` with `insertWithinTransaction()`, `claimPendingBatch()`, `markPublished()`, `markFailed()`, `moveToDlq()` (Section 4.5)
  - Create `src/application/ports/driven/i-abac-policy.repository.ts`: `IAbacPolicyRepository` (Section 4.3)
  - Create `src/application/ports/driven/i-alert.repository.ts`: `IAlertRepository` (Section 4.4)
  - Create `src/application/ports/driven/i-encryption.port.ts`: `IEncryptionPort` with `encrypt()`, `decrypt()`, `hmac()`, `encryptLarge()`, `decryptLarge()`
  - Create `src/application/ports/driven/i-otp.port.ts`: `IOtpPort` with `send()` supporting email and SMS channels
  - Create `src/application/ports/driven/i-cache.port.ts`: `ICachePort` with `get()`, `set()`, `del()`, `sismember()`, `sadd()`, `srem()`, `smembers()`, `incr()`, `expire()`
  - Create `src/application/ports/driven/i-queue.port.ts`: `IQueuePort` with `enqueue()`, `enqueueRepeatable()`
  - Create `src/application/ports/driven/i-metrics.port.ts`: `IMetricsPort` with `increment()`, `gauge()`, `histogram()`, `observe()`
  - Create `src/application/ports/driven/i-tracer.port.ts`: `ITracerPort` (Section 4.6)
  - Create `src/application/ports/driven/i-lock.port.ts`: `ILockPort` with `acquire()`, `release()`, `extend()` and `LockToken` / `LockOptions` types (Section 4.7)
  - _Implements: Req 1, Req 14_


### Phase 4: Infrastructure Adapters

- [x] 6. Implement database schema and MySQL module
  - Create `src/infrastructure/db/mysql/mysql.module.ts`: dynamic NestJS module wrapping a connection pool (`mysql2/promise`) with `min: 5`, `max: 20`, `acquireTimeoutMs: 5000`, `queueLimit: 50`
  - Create all SQL migration files in `migrations/` for every table in Section 6.1: `tenants`, `users`, `identities`, `credentials`, `sessions`, `refresh_tokens`, `jwt_signing_keys`, `otp_attempts`, `devices`, `client_apps`, `roles`, `permissions`, `role_permissions`, `user_roles`, `abac_policies`, `audit_logs`, `soc_alerts`, `domain_events`, `outbox_events`, `schema_versions`
  - Implement all partition strategies: `HASH(tenant_id)` for users/identities, `RANGE(expires_at)` for sessions/refresh_tokens, `RANGE(created_at)` for audit_logs/otp_attempts
  - Create migration runner that validates SHA-256 checksums against `schema_versions` on startup
  - _Implements: Req 1.1, Req 1.2, Req 6, Req 7, Req 8, Req 12_

- [x] 7. Implement MySQL repository adapters
  - Create `src/infrastructure/db/mysql/mysql-user.repository.ts`: implements `IUserRepository`; every query includes `WHERE tenant_id = ?`; uses optimistic locking (`version` column); routes reads to replica, writes to primary
  - Create `src/infrastructure/db/mysql/mysql-identity.repository.ts`: implements `IIdentityRepository`; `findByHash()` uses `uq_tenant_type_hash` index; `save()` throws `ConflictException(IDENTITY_ALREADY_EXISTS)` on duplicate key
  - Create `src/infrastructure/db/mysql/mysql-token.repository.ts`: implements `ITokenRepository`; `addToBlocklist()` stores `jti` in Redis sorted set with expiry score; `isBlocklisted()` is O(1) Redis ZSCORE check
  - Create `src/infrastructure/db/mysql/mysql-event-store.repository.ts`: implements `IEventStore`; `append()` uses `INSERT` with `uq_aggregate_seq` unique key to enforce optimistic concurrency; `loadEvents()` orders by `aggregate_seq ASC`
  - Create `src/infrastructure/db/mysql/mysql-outbox.repository.ts`: implements `IOutboxRepository`; `claimPendingBatch()` uses `SELECT ... FOR UPDATE SKIP LOCKED LIMIT 50`; `insertWithinTransaction()` participates in caller's transaction
  - Create `src/infrastructure/db/mysql/mysql-abac-policy.repository.ts`: implements `IAbacPolicyRepository`; `findByTenantId()` returns policies sorted by `priority DESC`; cache invalidated on `save()` / `delete()`
  - Create `src/infrastructure/db/mysql/mysql-alert.repository.ts`: implements `IAlertRepository`; `save()` is INSERT-only; `updateWorkflow()` only updates the `workflow` column; HMAC checksum verified on read
  - _Implements: Req 1.1, Req 1.2, Req 1.3, Req 7.5, Req 9.8, Req 12.1, Req 12.10_

  - [x] 7.1 Write property test for tenant isolation (Property 16)
    - **Property 16: No repository query returns rows belonging to a different tenant**
    - **Validates: Req 1.3**
    - Create user in tenantA; query with tenantB; assert result is null for all repository methods

  - [x] 7.2 Write integration tests for MySQL repositories
    - Signup race condition: two concurrent `save()` calls for same identity — exactly one succeeds, other throws `IDENTITY_ALREADY_EXISTS`
    - Optimistic lock conflict: two concurrent `update()` calls with same version — exactly one succeeds
    - Outbox SKIP LOCKED: two concurrent `claimPendingBatch()` calls — no event claimed by both
    - Audit log immutability: `UPDATE audit_logs` returns 0 rows affected
    - _Implements: Req 1.3, Req 2.7, Req 12.1_

- [x] 8. Implement Redis adapters (cache, session store, lock)
  - Create `src/infrastructure/cache/redis-cache.adapter.ts`: implements `ICachePort` using `ioredis`; wraps all commands with circuit breaker; supports Redis Cluster with `{userId}` hash tags for session key co-location
  - Create `src/infrastructure/session/redis-session.store.ts`: implements `ISessionStore`; stores session as Redis Hash with TTL; maintains `user-sessions:{tenantId}:{userId}` Sorted Set with creation timestamp as score; evicts oldest session when `max_sessions_per_user` limit reached; `extendTtl()` implements sliding TTL
  - Create `src/infrastructure/lock/redis-lock.adapter.ts`: implements `ILockPort`; `acquire()` uses `SET key value NX PX ttl`; `release()` uses Lua script (atomic check-and-delete); `extend()` uses Lua script (atomic check-and-PEXPIRE); exponential backoff with jitter on retry
  - _Implements: Req 8.1–8.4, Req 14.1–14.6_

  - [x] 8.1 Write property test for distributed lock exclusivity (Property 15)
    - **Property 15: At most one process holds a given lock key at any point in time**
    - **Validates: Req 14.6**
    - Concurrently attempt to acquire same lock key 10 times; assert exactly 1 succeeds

  - [x] 8.2 Write integration tests for Redis session store
    - Session TTL expiry: create session, wait for TTL, assert `findById()` returns null
    - OTP single-use: `GETDEL` returns value on first call, null on second
    - Session LRU eviction: create `max_sessions + 1` sessions; assert oldest is evicted
    - Sliding TTL: access session, assert TTL is reset to full `session_ttl_s`
    - _Implements: Req 8.1–8.4, Req 6.2_

- [x] 9. Implement encryption adapter
  - Create `src/infrastructure/encryption/aes256-gcm.encryption.adapter.ts`: implements `IEncryptionPort`
  - `encrypt(plaintext, context, tenantId)`: derives context key via `HKDF(masterKey, tenantId || context)`, generates 12-byte random IV, encrypts with AES-256-GCM, serializes as `base64(iv).base64(tag).base64(ciphertext).kid`
  - `decrypt(encryptedValue, context, tenantId)`: parses serialized format, selects master key by `kid` (supports deprecated keys), derives context key, decrypts and verifies GCM auth tag
  - `hmac(value, context)`: computes HMAC-SHA256 using context-derived key; deterministic for same input
  - `encryptLarge()` / `decryptLarge()`: envelope encryption for fields >4KB (DEK encrypted with KEK)
  - Implement startup validation in `validateEncryptionKeys()`: roundtrip test for every `EncryptionContext`; cross-context isolation check (Section 7.5)
  - _Implements: Req 13.1–13.9_

  - [x] 9.1 Write property test for encryption roundtrip (Property 7)
    - **Property 7: decrypt(encrypt(p, ctx), ctx) = p for all plaintexts and contexts**
    - **Validates: Req 13.1, Req 13.2**
    - Use `fc.string({ minLength: 1, maxLength: 1000 })` × all `EncryptionContext` values; assert roundtrip equality

  - [x] 9.2 Write property test for HMAC determinism (Property 8)
    - **Property 8: hmac(v, ctx) = hmac(v, ctx) — same input always produces same output**
    - **Validates: Req 13.8**
    - Use `fc.string()` × all `EncryptionContext` values; assert two calls with same args produce identical output

  - [x] 9.3 Write property test for cross-context encryption isolation
    - **Validates: Req 1.4, Req 13.7**
    - Encrypt with contextA; attempt decrypt with contextB; assert GCM auth tag mismatch (decryption fails)

- [x] 10. Implement BullMQ queue adapter and workers
  - Create `src/infrastructure/queue/bullmq-queue.adapter.ts`: implements `IQueuePort`; wraps BullMQ `Queue` with per-queue concurrency limits from Section 11.2; `enqueueRepeatable()` for scheduled jobs (Tor list refresh every 6h)
  - Create `src/infrastructure/queue/workers/otp-send.worker.ts`: BullMQ worker processing `otp-send` queue; concurrency 5; dispatches via `IOtpPort`
  - Create `src/infrastructure/queue/workers/audit-write.worker.ts`: BullMQ worker processing `audit-write` queue; concurrency 20; writes to `audit_logs` table with HMAC checksum
  - Create `src/infrastructure/queue/workers/soc-alert.worker.ts`: BullMQ worker processing `soc-alert` queue; concurrency 3; persists `SocAlert` and emits WebSocket event
  - Create `src/infrastructure/queue/workers/outbox-relay.worker.ts`: BullMQ worker polling `outbox_events` every 500ms using `claimPendingBatch(50)`; publishes to BullMQ; marks published; moves to DLQ after 5 failures
  - _Implements: Req 4.5, Req 15, Req 19 (Property 19)_

  - [x] 10.1 Write unit tests for outbox relay worker
    - Successful relay: pending event → published status
    - Retry on failure: failed event increments attempt count
    - DLQ after 5 failures: event moved to DLQ, SOC alert emitted
    - _Implements: Req 4.5_

- [x] 11. Implement OTP, GeoIP, and metrics/tracing adapters
  - Create `src/infrastructure/otp/firebase-otp.adapter.ts`: implements `IOtpPort` for SMS via Firebase; wrapped with circuit breaker (3000ms timeout, 40% error threshold)
  - Create `src/infrastructure/otp/smtp-otp.adapter.ts`: implements `IOtpPort` for email via SMTP; fallback when Firebase circuit breaker is open
  - Create `src/infrastructure/geo/maxmind-geo.adapter.ts`: wraps `maxmind` npm package with local GeoLite2 DB; `lookup(ip)` returns `{ lat, lon, country, city }`; circuit breaker (100ms timeout, 20% error threshold); returns `null` on open (geo score defaults to 0.0)
  - Create `src/infrastructure/metrics/prom-client.metrics.adapter.ts`: implements `IMetricsPort`; registers all counters, gauges, and histograms from Section 13.4; exposes `/metrics` endpoint
  - Create `src/infrastructure/tracing/otel-tracer.adapter.ts`: implements `ITracerPort`; configures OTel SDK with `UicpSampler` (Section 13.3); propagates W3C TraceContext; `withSpan()` always ends span on exception
  - _Implements: Req 6.1, Req 11.4, Req 15.1, Req 15.3_


### Phase 5: Application Layer

- [x] 12. Implement application services
  - Create `src/application/services/credential.service.ts`: `hash(rawPassword)` using bcrypt with adaptive rounds + pepper; `verify(password, credential)` using timing-safe bcrypt compare; `rehash(password)` for async background rehash when rounds change; `needsRehash(credential)` checks if stored rounds differ from current
  - Create `src/application/services/token.service.ts`: `mintAccessToken(user, session)` — RS256 JWT with 15-min TTL, embedded `roles`/`perms`/`mfa`/`amr` claims (Section 8.1); `mintRefreshToken(userId, familyId)` — RS256 JWT with 7-day TTL and `fid` claim (Section 8.2); `parseRefreshToken()`, `parseAccessToken()`, `rotateSigningKey()`
  - Create `src/application/services/session.service.ts`: `createSession()` — stores Redis Hash + Sorted Set, enforces `max_sessions_per_user` LRU eviction; `invalidate()`, `invalidateAll()`, `listByUser()`, `extendTtl()`, `setStatus()`, `addTrustedDevice()`; parses User-Agent string for browser/OS/device type
  - Create `src/application/services/otp.service.ts`: `generate()` — `crypto.randomInt(0, 999999)` zero-padded to 6 digits; `store(userId, purpose, code)` — Redis SET with 300s TTL; `verifyAndConsume(userId, code, purpose)` — atomic Redis `GETDEL` + timing-safe compare
  - Create `src/application/services/distributed-lock.service.ts`: wraps `ILockPort` with retry budget tracking from CLS context; `withLock(key, ttl, fn)` helper
  - Create `src/application/services/idempotency.service.ts`: `check(key)` — Redis GET for cached response; `store(key, response)` — Redis SET with 24h TTL; `isReplay()` helper
  - _Implements: Req 2.8, Req 2.9, Req 3.9, Req 6.1–6.9, Req 7.1–7.9, Req 8.1–8.10_

  - [x] 12.1 Write property test for credential pepper consistency (Property 17)
    - **Property 17: verify(p, hash(p, pepper), pepper) = true; verify(p, hash(p, pepper), wrong_pepper) = false**
    - **Validates: Req 2.9**
    - Use `validPassword()` arbitrary; assert hash+verify roundtrip succeeds; assert wrong pepper fails

  - [x] 12.2 Write unit tests for OTP service
    - `verifyAndConsume()` succeeds on first call, throws `ALREADY_USED` on second (single-use guarantee)
    - Expired OTP (TTL elapsed) throws `OTP_EXPIRED`
    - Wrong code throws `INVALID_OTP`
    - Timing-safe comparison used (no early return on mismatch)
    - _Implements: Req 6.2–6.5, Req 6.8_

- [x] 13. Implement command handlers — authentication flows
  - Create `src/application/commands/signup-email/signup-email.handler.ts`: implements full signup flow — `Email.create()` + `RawPassword.create()`, HMAC lookup for duplicate check, distributed lock on identity value, `User.createWithEmail()`, `user.linkIdentity()`, credential hash, `IUserRepository.save()`, `IOutboxRepository.insertWithinTransaction()`, OTP dispatch via queue
  - Create `src/application/commands/login/login.handler.ts`: implements 14-step login flow (Section 5.1) — identity lookup, timing-safe null check, UEBA scoring, auth policy eval, credential verify, session creation with distributed lock, token minting, MFA branch, outbox events, async rehash
  - Create `src/application/commands/refresh-token/refresh-token.handler.ts`: implements pessimistic lock + reuse detection flow (Section 5.2) — parse token, blocklist check, acquire family lock, check revocation status, rotate token, emit `TokenRefreshedEvent` or `TokenReuseDetectedEvent`
  - Create `src/application/commands/verify-otp/verify-otp.handler.ts`: implements atomic OTP consume flow (Section 5.3) — `OtpService.verifyAndConsume()`, `user.verifyIdentity()`, event store append, outbox events, saga trigger for `IDENTITY_VERIFICATION` purpose
  - Create `src/application/commands/logout/logout.handler.ts`: invalidate current session, add access token JTI to blocklist with remaining TTL, emit outbox event
  - Create `src/application/commands/logout-all/logout-all.handler.ts`: implements flow from Section 5.4 — list all sessions, invalidate each, blocklist all JTIs, revoke all token families
  - Create `src/application/commands/oauth-callback/oauth-callback.handler.ts`: implements OAuth flow (Section 5.5) — state verification, code exchange, `findByProviderSub()`, upsert identity, create session, mint tokens
  - Create `src/application/commands/change-password/change-password.handler.ts`: verify current password, hash new password, update credential, invalidate all sessions except current, emit `PasswordChangedEvent` to outbox within same transaction
  - Create `src/application/commands/rotate-keys/rotate-keys.handler.ts`: generate RSA-4096 key pair, assign new `kid`, persist encrypted private key, update JWKS, begin signing with new key
  - _Implements: Req 2.1–2.9, Req 3.1–3.10, Req 4.1–4.5, Req 5.1–5.7, Req 6.1–6.9, Req 7.1–7.9_

  - [x] 13.1 Write property test for idempotency consistency (Property 14)
    - **Property 14: Two requests with the same idempotency key return identical responses**
    - **Validates: Req 2.8**
    - Use `fc.uuid()` as idempotency key; call signup twice with same key; assert second response has `x-idempotency-replayed: true` and identical body

  - [x] 13.2 Write property test for optimistic lock concurrency (Property 3)
    - **Property 3: Concurrent updates with same version — exactly one succeeds, rest throw VERSION_CONFLICT**
    - **Validates: Req 2.7**
    - Use `fc.asyncProperty` with `Promise.allSettled` on 2 concurrent updates; assert exactly 1 fulfilled, 1 rejected with `VERSION_CONFLICT`

  - [x] 13.3 Write integration tests for signup and login flows
    - Duplicate identity returns HTTP 409 `IDENTITY_ALREADY_EXISTS`
    - Login with DELETED account returns HTTP 401 `ACCOUNT_DELETED`
    - Login with SUSPENDED account returns HTTP 401 `ACCOUNT_SUSPENDED` with `retryAfter`
    - Login with PENDING account returns HTTP 401 `ACCOUNT_NOT_ACTIVATED`
    - MFA required flow returns HTTP 202 with `mfaRequired: true`
    - Token reuse returns HTTP 401 `REFRESH_TOKEN_REUSE` and revokes all family tokens
    - _Implements: Req 2.3, Req 3.5–3.7, Req 7.4_

- [x] 14. Implement query handlers and sagas
  - Create `src/application/queries/get-user/get-user.handler.ts`: load user by ID with tenant isolation, decrypt PII fields, return profile
  - Create `src/application/queries/get-user-sessions/get-user-sessions.handler.ts`: list sessions from Redis + DB merge, enrich with device info
  - Create `src/application/queries/list-audit-logs/list-audit-logs.handler.ts`: cursor-paginated query with HMAC integrity verification on each row
  - Create `src/application/queries/get-threat-history/get-threat-history.handler.ts`: load SOC alerts for user with signal breakdown
  - Create `src/application/queries/get-jwks/get-jwks.handler.ts`: load all active + deprecated signing keys, return JWK Set (RFC 7517)
  - Create `src/application/queries/validate-token/validate-token.handler.ts`: verify RS256 signature, check `exp`/`iss`/`aud` claims, O(1) Redis blocklist check — zero DB round trips for access tokens
  - Create `src/application/sagas/identity-verification.saga.ts`: implements `IdentityVerificationSaga` (Section 5.7) — send welcome email, write audit log, trigger provisioning; compensation on failure
  - _Implements: Req 7.7, Req 8.7, Req 12.5_


### Phase 6: Resilience Infrastructure

- [x] 15. Implement circuit breakers and retry budget
  - Create `src/infrastructure/resilience/circuit-breaker.ts`: generic `CircuitBreaker<T>` class implementing CLOSED→OPEN→HALF_OPEN state machine (Section 11.1); per-dependency config table (MySQL: 5000ms/50%/10/30s, Redis: 200ms/30%/20/10s, Firebase: 3000ms/40%/5/60s, GeoIP: 100ms/20%/10/30s); emits `uicp_circuit_breaker_state` metric on state change
  - Create `src/infrastructure/resilience/retry-budget.ts`: `RetryBudget` stored in CLS context; `consume()` returns false when budget (default 3) exhausted; prevents retry storms
  - Wrap MySQL pool, Redis client, Firebase OTP, and MaxMind GeoIP adapters with their respective circuit breakers
  - Implement fallbacks: Redis open → session reads fall back to MySQL; rate limiting falls back to in-memory token bucket; distributed locks fall back to MySQL `GET_LOCK()` advisory locks
  - _Implements: Req 15.1–15.6_

  - [x] 15.1 Write unit tests for circuit breaker state machine
    - CLOSED → OPEN after error threshold exceeded
    - OPEN → HALF_OPEN after reset timeout
    - HALF_OPEN → CLOSED on probe success
    - HALF_OPEN → OPEN on probe failure
    - Fallback invoked when circuit is OPEN
    - _Implements: Req 15.1, Req 15.2_

- [x] 16. Implement distributed lock service and outbox relay
  - Wire `DistributedLockService` into `SignupEmailHandler`, `LoginHandler`, and `RefreshTokenHandler` for the three required lock points (Req 14.5)
  - Implement MySQL advisory lock fallback in `DistributedLockService` for when Redis circuit breaker is open
  - Verify `OutboxRelayWorker` uses `SKIP LOCKED` and that multiple concurrent relay workers do not double-process events
  - _Implements: Req 14.1–14.6, Req 15.2_

  - [x] 16.1 Write property test for OTP single-use guarantee (Property 5)
    - **Property 5: verify(C) succeeds ⟹ verify(C) on subsequent call throws ALREADY_USED**
    - **Validates: Req 6.2, Req 6.4**
    - Generate arbitrary OTP codes; assert first verify succeeds, second throws `ALREADY_USED`

- [x] 17. Implement rate limiter middleware
  - Create `src/interface/http/middleware/rate-limiter.middleware.ts`: token-bucket rate limiter using Redis; per-IP and per-user buckets; enforces limits from Section 17.1 (login: 20/min/IP, signup: 10/min/IP, OTP verify: 10/min/user, password reset: 3/min/IP)
  - Implement in-memory token bucket fallback when Redis circuit breaker is open
  - Implement adaptive rate limit multiplier (Section 12.6): reads `rate-limit-multiplier:{tenantId}` from Redis; adjusts limits based on error rate
  - Return HTTP 429 with `Retry-After` header when limit exceeded
  - _Implements: Req 3.10, Req 4.4, Req 6.9_

  - [x] 17.1 Write property test for rate limit monotonicity (Property 6)
    - **Property 6: Token bucket remaining is always in [0, capacity] — never negative, never exceeds capacity**
    - **Validates: Req 3.10, Req 4.4**
    - Use `fc.integer({ min: 1, max: 100 })` for capacity and `fc.integer({ min: 1, max: 1000 })` for request count; assert all `remaining` values are in bounds


### Phase 7: Security Systems

- [x] 18. Implement UEBA engine and threat scoring
  - Create `src/application/services/ueba/velocity-analyzer.ts`: four sliding window counters in Redis (user 1-min threshold 5, user 5-min threshold 15, IP 1-min threshold 10, IP 10-min threshold 30); weighted equally at 0.25 each; uses `INCR` + `EXPIRE`
  - Create `src/application/services/ueba/geo-analyzer.ts`: loads last known location from Redis (`geo-baseline:{tenantId}:{userId}`); computes haversine distance; scores 1.0 for impossible travel (>900 km/h), 0.6 for country change, 0.2 for city change, 0.0 otherwise; uses MaxMind GeoIP adapter; updates baseline on successful login
  - Create `src/application/services/ueba/device-analyzer.ts`: computes device fingerprint as `SHA-256(ua:lang:screen:tz:platform).slice(0,16)`; checks `SMEMBERS devices:{tenantId}:{userId}`; scores 0.0 for known, 0.5 for unknown with existing devices, 0.1 for unknown with no devices
  - Create `src/application/services/ueba/credential-stuffing-analyzer.ts`: cross-tenant and per-tenant sliding 10-min windows; scores 1.0 when global failures >30, 0.7 when >15, 0.5 when tenant failures >10
  - Create `src/application/services/ueba/tor-exit-node-checker.ts`: checks `SISMEMBER tor-exit-nodes {ip}`; scores 0.4 for Tor exit nodes; BullMQ repeatable job updates list every 6h from Tor Project bulk exit list
  - Create `src/application/services/ueba/ueba-engine.ts`: orchestrates all five analyzers via `Promise.allSettled()` (partial failure safe); computes weighted composite score (Section 10.2); classifies kill-chain stage (Section 10.3); creates SOC alert when score >0.75; locks account in Redis when score >0.90
  - _Implements: Req 11.1–11.10_

  - [x] 18.1 Write property test for threat score bounds (Property 12)
    - **Property 12: UEBA composite score is always in [0.0, 1.0]**
    - **Validates: Req 11.1, Req 11.8**
    - Use `fc.float({ min: 0.0, max: 1.0, noNaN: true })` for each signal; assert composite score is in [0.0, 1.0] across 10,000 runs

  - [x] 18.2 Write unit tests for each UEBA analyzer
    - VelocityAnalyzer: score increases with request count; caps at 1.0
    - GeoAnalyzer: impossible travel (>900 km/h) → 1.0; country change → 0.6; city change → 0.2; same location → 0.0
    - DeviceAnalyzer: known device → 0.0; unknown with existing devices → 0.5; new user unknown device → 0.1
    - CredentialStuffingAnalyzer: >30 global failures → 1.0
    - TorExitNodeChecker: Tor IP → 0.4; non-Tor → 0.0
    - _Implements: Req 11.2–11.7_

- [x] 19. Implement SOC alerting and WebSocket dashboard
  - Create `src/interface/ws/soc-dashboard.gateway.ts`: Socket.IO gateway; JWT authentication in handshake; auto-join to `tenant:{tenantId}:soc` room on connect; emits `soc:alert:created`, `soc:alert:updated`, `soc:metrics` events (Section 10.6); `soc:metrics` emitted every 30s
  - Implement SOC alert workflow endpoints in `AdminController`: `PATCH /soc/alerts/{id}/acknowledge`, `PATCH /soc/alerts/{id}/resolve`, `PATCH /soc/alerts/{id}/false-positive`; state machine transitions (Section 10.5); `false-positive` notifies adaptive threshold tuner
  - Implement `GET /soc/alerts` with filtering by workflow state, threat score range, kill chain stage, date range
  - Implement `POST /soc/users/{userId}/lock` and `POST /soc/users/{userId}/revoke-sessions`
  - Verify HMAC checksum on every `SocAlert` read; throw integrity violation exception and emit critical metric on mismatch
  - _Implements: Req 12.1–12.10_

  - [x] 19.1 Write unit tests for SOC alert workflow state machine
    - OPEN → ACKNOWLEDGED → RESOLVED valid transitions
    - OPEN → FALSE_POSITIVE valid from any state
    - HMAC checksum failure throws integrity violation exception
    - _Implements: Req 12.2–12.4, Req 12.10_

- [x] 20. Implement ABAC policy engine with JIT compilation
  - Create `src/application/services/abac/abac-policy-engine.ts`: loads policies from `IAbacPolicyRepository` (LRU cache 100 tenants, 60s TTL); sorts by `priority DESC`; evaluates subject/resource/action conditions; deny-override algorithm; implicit deny default
  - Implement JIT compilation: DSL AST → JavaScript function string → `new Function(...)`; cache compiled functions in LRU(500) by `policyId + version`
  - Implement DSL validator: parse DSL condition against grammar (Section 3.6) before persisting; return HTTP 400 with descriptive error on invalid DSL
  - Implement `POST /iam/policies/evaluate` dry-run and `GET /iam/policies/simulate` endpoints
  - Invalidate tenant policy cache immediately on policy create/update/delete
  - _Implements: Req 9.1–9.11_

  - [x] 20.1 Write property test for ABAC JIT determinism (Property 20)
    - **Property 20: JIT-compiled policy function produces same result as DSL interpreter for all contexts**
    - **Validates: Req 9.7**
    - Generate arbitrary evaluation contexts; assert `compiledFn(context) === interpretDsl(condition)(context)` across 1,000 runs

  - [x] 20.2 Write property test for ABAC deny-override (Property 11 — full engine test)
    - **Property 11: DENY policy overrides ALLOW regardless of priority ordering**
    - **Validates: Req 9.3**
    - Generate policy sets with arbitrary priorities; assert any matching DENY always produces DENY decision


### Phase 8: Interface Layer

- [x] 21. Implement HTTP guards, interceptors, pipes, and filters
  - Create `src/interface/http/guards/tenant.guard.ts`: extracts `X-Tenant-ID` header; validates UUID format; if JWT present, verifies `tid` claim matches header — rejects with HTTP 403 if mismatch; sets `tenantId` on request
  - Create `src/interface/http/guards/jwt-auth.guard.ts`: verifies RS256 signature, `exp`, `iss`, `aud` claims; checks `jti` against Redis blocklist; sets `userId`, `sessionId`, `roles`, `perms` on request
  - Create `src/interface/http/interceptors/cls-context.interceptor.ts`: `AsyncLocalStorage.run()` with `{ requestId, tenantId, userId, traceId, sessionId }` from request; populates CLS store for entire async call stack
  - Create `src/interface/http/interceptors/idempotency.interceptor.ts`: reads `X-Idempotency-Key` header; checks Redis cache; returns cached response with `x-idempotency-replayed: true` on hit; stores response on miss
  - Create `src/interface/http/interceptors/response-envelope.interceptor.ts`: wraps all responses in `{ data, meta: { requestId, timestamp } }`
  - Create `src/interface/http/pipes/zod-validation.pipe.ts`: Zod schema parse + transform; throws `SchemaValidationException(400)` with field path on failure
  - Create `src/interface/http/filters/global-exception.filter.ts`: maps `DomainException`, `AuthenticationException`, `ConflictException`, `InfrastructureException` to appropriate HTTP status codes; emits Pino log + Prometheus counter on every error
  - _Implements: Req 1.6, Req 2.8, Req 3.8_

  - [x] 21.1 Write unit tests for TenantGuard and JwtAuthGuard
    - TenantGuard: JWT `tid=A` + header `X-Tenant-ID=B` → HTTP 403
    - TenantGuard: missing `X-Tenant-ID` header → HTTP 400
    - JwtAuthGuard: expired token → HTTP 401
    - JwtAuthGuard: blocklisted `jti` → HTTP 401
    - JwtAuthGuard: invalid signature → HTTP 401
    - _Implements: Req 1.6, Req 7.7_

- [x] 22. Implement HTTP controllers
  - Create `src/interface/http/controllers/auth.controller.ts`: all 14 endpoints from Section 17.1 (`/auth/*`); apply `TenantGuard`, `ZodValidationPipe`, `IdempotencyInterceptor` per endpoint; apply rate limit decorators
  - Create `src/interface/http/controllers/session.controller.ts`: `GET /users/me/sessions`, `DELETE /users/me/sessions/{id}`, `GET /users/me/devices`, `DELETE /users/me/devices/{id}`
  - Create `src/interface/http/controllers/user.controller.ts`: `GET /users/me`, `PATCH /users/me`, `DELETE /users/me`, `GET /users/me/identities`, `POST /users/me/identities`, `DELETE /users/me/identities/{id}`, `GET /users/me/permissions`
  - Create `src/interface/http/controllers/admin.controller.ts`: all admin endpoints from Section 17.4 (`/admin/*`) and SOC endpoints (`/soc/*`); all IAM endpoints from Section 17.3 (`/iam/*`)
  - Create `src/interface/http/controllers/jwks.controller.ts`: `GET /.well-known/jwks.json` with `Cache-Control: public, max-age=3600`; `GET /.well-known/openid-configuration`
  - _Implements: Req 2, Req 3, Req 4, Req 5, Req 6, Req 7, Req 8, Req 9, Req 10, Req 12_

  - [x] 22.1 Write integration tests for HTTP controllers
    - `POST /auth/signup` with idempotency key: second call returns cached response
    - `POST /auth/login` rate limit: 21st request returns HTTP 429
    - `GET /.well-known/jwks.json`: returns valid JWK Set with `Cache-Control` header
    - `POST /iam/policies/evaluate`: dry-run returns evaluation result with matched nodes
    - _Implements: Req 2.8, Req 3.10, Req 7.6, Req 9.10_

- [x] 23. Implement gRPC handler for token validation
  - Create `src/interface/grpc/token-validate.grpc.handler.ts`: implements `ValidateToken` RPC (Section 5.6); verifies RS256 signature, claims, and Redis blocklist; returns `TokenClaims` or error status; zero DB round trips for access tokens
  - Create `src/interface/grpc/auth.grpc.handler.ts`: internal service-to-service auth operations
  - Configure gRPC server in `main.ts` as microservice transport alongside HTTP
  - _Implements: Req 7.10_

- [x] 24. Checkpoint — Ensure all tests pass
  - Run full test suite: `jest --runInBand --coverage`
  - Verify all property-based tests pass (Properties 1–20)
  - Verify all integration tests pass against real MySQL and Redis (test containers)
  - Ensure all TypeScript compiles with zero errors (`tsc --noEmit`)
  - Ensure all tests pass, ask the user if questions arise.


### Phase 9: Adaptive Systems

- [x] 25. Implement server load monitor and adaptive bcrypt
  - Create `src/infrastructure/adaptive/server-load-monitor.ts`: samples CPU (`os.cpus()`), memory (`process.memoryUsage()`), and event loop lag (`setImmediate` + `hrtime`) every 5 seconds; applies EMA with α=0.15 (Section 12.1); computes composite load score `0.30·cpu + 0.30·mem + 0.40·min(1.0, lag/100)`; exposes `getCompositeScore()`
  - Create `src/infrastructure/adaptive/adaptive-bcrypt.ts`: `calibrateBcryptRounds()` runs 5 samples, computes P95, adjusts rounds ±1 within [10, 13] to target 200ms (Section 12.2); runs at startup and every 30 minutes; load-aware: uses `MIN_ROUNDS` when load score >0.80; logs all changes with `uicp_adaptive_parameter_change_total` metric
  - _Implements: Req 3.9, Req 15_

  - [x] 25.1 Write property test for bcrypt rounds floor (Property 13)
    - **Property 13: getBcryptRounds() ≥ 10 under any load score**
    - **Validates: Req 2.9**
    - Use `fc.float({ min: 0.0, max: 1.0 })` for load score; mock `ServerLoadMonitor`; assert rounds never below 10 across 1,000 runs

- [x] 26. Implement adaptive cache TTL, DB pool, and queue concurrency
  - Create `src/infrastructure/adaptive/adaptive-cache.ts`: per-key-type hit rate tracking (sliding window of last 1000 ops); TTL multiplier table (Section 12.3); ±10% jitter to prevent thundering herd; `getAdaptiveTtl(baseTtl, keyType)` used by `RedisCacheAdapter`
  - Create `src/infrastructure/adaptive/adaptive-db-pool.ts`: monitors pool metrics every 10s; expands by 2 when `waiting > 5`; shrinks by 1 when `idle > 2×min`; bounded by `[min=5, max=20]` (Section 12.4)
  - Create `src/infrastructure/adaptive/adaptive-queue-concurrency.ts`: per-queue tuning based on load score + queue depth (Section 12.5); `getAdaptiveConcurrency(queue)` used by BullMQ workers
  - Create `src/infrastructure/adaptive/adaptive-rate-limit.ts`: adjusts rate limit multiplier based on 5xx error rate (Section 12.6); stores multiplier in Redis; cycle every 30s
  - Create `src/infrastructure/adaptive/adaptive-tuning-engine.ts`: orchestrates all adaptive components; `ThresholdTuner` for UEBA false-positive feedback loop (Section 10.4); logs all parameter changes via `AdaptiveChangeLog`
  - _Implements: Req 15, Req 12 (SOC false-positive feedback)_


### Phase 10: Observability

- [x] 27. Implement structured Pino logging with CLS correlation
  - Configure `pino-http` in `main.ts` with NDJSON output, `pino-redact` for PII paths (`['email', 'password', 'phone', 'ip', '*.email', '*.phone']`), and log level from `LOG_LEVEL` env var
  - Create Pino child logger factory that auto-injects CLS context (`requestId`, `traceId`, `tenantId`, `userId`, `sessionId`) into every log line (Section 13.6)
  - Add `durationMs` measurement wrapper (`measure()`) for key operations: login, signup, token validation, UEBA scoring
  - Ensure all error logs include `errorCode`, `errorCategory`, `httpStatus`, `ipHash` (never raw IP), `threatScore`
  - _Implements: Req 1 (audit trail), Req 13.6_

- [x] 28. Implement OpenTelemetry tracing
  - Configure OTel SDK in `main.ts` with `UicpSampler` (100% for errors/security events, 10% for normal traffic, 100% for slow requests >400ms)
  - Instrument all command handlers, repository methods, Redis commands, and UEBA engine with spans following the hierarchy in Section 13.1
  - Add standard attributes to all spans: `service.name`, `service.version`, `tenant.id`, `request.id`, `user.id`
  - Add DB span attributes: `db.system`, `db.operation`, `db.table`, `db.rows_affected`, `db.duration_ms` (no `db.statement` — PII risk)
  - Add security event span attributes: `security.event_type`, `security.threat_score`, `security.kill_chain_stage`, `security.ip_hash`
  - Wire `ITracerPort` implementation into `OtelTracerAdapter`; propagate W3C TraceContext headers
  - _Implements: Req 13.1–13.3_

- [x] 29. Implement Prometheus metrics
  - Register all counters, gauges, and histograms from Section 13.4 in `PromClientMetricsAdapter`
  - Wire `IMetricsPort` calls into: command handlers (auth attempts, signup, OTP, token), circuit breaker state changes, outbox relay, adaptive parameter changes
  - Expose `/metrics` endpoint (Prometheus scrape target)
  - Create `prometheus-alerts.yaml` with all 5 alert rules from Section 13.5: `UicpCircuitBreakerOpen`, `UicpHighErrorRate`, `UicpThreatScoreSpike`, `UicpOutboxDlqGrowing`, `UicpDbPoolExhausted`
  - _Implements: Req 15.3_


### Phase 11: Testing

- [x] 30. Write remaining property-based tests for all 20 correctness properties
  - [x] 30.1 Write property test for User aggregate state machine (Property 1 — if not already done in task 3.1)
    - **Property 1: User state machine never reaches an invalid transition**
    - **Validates: Req 3.5, Req 3.6, Req 3.7**

  - [x] 30.2 Write property test for Token family revocation completeness (Property 2)
    - **Property 2: When token reuse is detected, ALL tokens in the family are revoked**
    - **Validates: Req 7.4**
    - Create a token family with N tokens; trigger reuse detection; assert all N tokens have `revoked=true`

  - [ ]* 30.3 Write property test for optimistic lock concurrency (Property 3 — if not already done in task 13.2)
    - **Property 3: Concurrent updates with same version — exactly one succeeds, rest throw VERSION_CONFLICT**
    - **Validates: Req 2.7**

  - [ ]* 30.4 Write property test for event store append ordering (Property 4)
    - **Property 4: Concurrent appends with same aggregate_seq — exactly one succeeds, rest throw VERSION_CONFLICT**
    - **Validates: Req 7 (event sourcing)**
    - Use `Promise.allSettled` on 2 concurrent `eventStore.append()` calls with same `aggregateSeq`; assert exactly 1 fulfilled

  - [ ]* 30.5 Write property test for OTP single-use (Property 5 — if not already done in task 16.1)
    - **Property 5: verify(C) succeeds ⟹ verify(C) on subsequent call throws ALREADY_USED**
    - **Validates: Req 6.2, Req 6.4**

  - [ ]* 30.6 Write property test for rate limit monotonicity (Property 6 — if not already done in task 17.1)
    - **Property 6: Token bucket remaining is always in [0, capacity]**
    - **Validates: Req 3.10, Req 4.4**

  - [ ]* 30.7 Write property test for encryption roundtrip (Property 7 — if not already done in task 9.1)
    - **Property 7: decrypt(encrypt(p, ctx), ctx) = p**
    - **Validates: Req 13.1, Req 13.2**

  - [ ]* 30.8 Write property test for HMAC determinism (Property 8 — if not already done in task 9.2)
    - **Property 8: hmac(v, ctx) = hmac(v, ctx)**
    - **Validates: Req 13.8**

  - [ ]* 30.9 Write property test for session expiry (Property 9)
    - **Property 9: t > session.expiresAt ⟹ findById(session.id) = null**
    - **Validates: Req 8.1**
    - Create session with short TTL; advance time past expiry; assert `findById()` returns null

  - [ ]* 30.10 Write property test for audit log immutability (Property 10)
    - **Property 10: UPDATE audit_logs WHERE id = A.id → 0 rows affected**
    - **Validates: Req 12.1**
    - Insert audit log; attempt UPDATE; assert 0 rows affected; assert original row unchanged

  - [ ]* 30.11 Write property test for ABAC deny-override (Property 11 — if not already done in tasks 4.2 / 20.2)
    - **Property 11: Any matching DENY policy overrides all ALLOW policies**
    - **Validates: Req 9.3**

  - [ ]* 30.12 Write property test for threat score bounds (Property 12 — if not already done in task 18.1)
    - **Property 12: UEBA composite score ∈ [0.0, 1.0]**
    - **Validates: Req 11.1, Req 11.8**

  - [ ]* 30.13 Write property test for bcrypt rounds floor (Property 13 — if not already done in task 25.1)
    - **Property 13: getBcryptRounds() ≥ 10 under any load score**
    - **Validates: Req 2.9**

  - [ ]* 30.14 Write property test for idempotency consistency (Property 14 — if not already done in task 13.1)
    - **Property 14: Same idempotency key always returns same response**
    - **Validates: Req 2.8**

  - [ ]* 30.15 Write property test for distributed lock exclusivity (Property 15 — if not already done in task 8.1)
    - **Property 15: At most one process holds a given lock key at any point in time**
    - **Validates: Req 14.6**

  - [ ]* 30.16 Write property test for tenant isolation (Property 16 — if not already done in task 7.1)
    - **Property 16: No repository query returns rows belonging to a different tenant**
    - **Validates: Req 1.3**

  - [ ]* 30.17 Write property test for credential pepper consistency (Property 17 — if not already done in task 12.1)
    - **Property 17: verify(p, hash(p, pepper), pepper) = true; wrong pepper = false**
    - **Validates: Req 2.9**

  - [ ]* 30.18 Write property test for event store ordering (Property 18 — if not already done in task 3.2)
    - **Property 18: loadEvents() always returns events in ascending aggregate_seq order**
    - **Validates: Req 2.1 (event sourcing)**

  - [ ]* 30.19 Write property test for outbox at-least-once delivery (Property 19)
    - **Property 19: Every outbox event eventually reaches status PUBLISHED or DLQ — never stays PENDING indefinitely**
    - **Validates: Req 4.5**
    - Insert N outbox events; run relay worker; assert all events reach terminal status within timeout

  - [ ]* 30.20 Write property test for ABAC JIT determinism (Property 20 — if not already done in task 20.1)
    - **Property 20: JIT-compiled policy function matches DSL interpreter for all contexts**
    - **Validates: Req 9.7**

- [ ] 31. Write domain unit tests
  - [ ]* 31.1 Write unit tests for all domain value objects (if not already done in task 2.2)
    - Cover all invariant violations from Section 3.8
    - _Implements: Req 2.4, Req 2.5, Req 2.6_

  - [ ]* 31.2 Write unit tests for User and Session aggregate state machines (if not already done in task 3.3)
    - All valid and invalid state transitions
    - `pullDomainEvents()` returns and clears uncommitted events
    - `fromEvents()` correctly reconstitutes aggregate from event sequence
    - _Implements: Req 2, Req 3, Req 8_

  - [ ]* 31.3 Write unit tests for ABAC condition DSL parser
    - Valid DSL expressions parse without error
    - Invalid DSL expressions throw parse error with descriptive message
    - `evaluate()` returns correct boolean for all operator types (`==`, `!=`, `IN`, `NOT IN`, `CONTAINS`, `AND`, `OR`, `NOT`)
    - _Implements: Req 9.1, Req 9.2, Req 9.11_

- [ ] 32. Write end-to-end integration tests
  - [ ]* 32.1 Write integration test for full signup → OTP verify → login flow
    - Signup creates user in PENDING status
    - OTP verify activates user
    - Login returns access + refresh tokens
    - _Implements: Req 2.1, Req 6.6, Req 3.1_

  - [ ]* 32.2 Write integration test for token refresh and reuse detection
    - Refresh returns new token pair
    - Submitting old (rotated) refresh token triggers family revocation and HTTP 401
    - _Implements: Req 7.3, Req 7.4_

  - [ ]* 32.3 Write integration test for OAuth login flow
    - Mock OAuth provider; verify state CSRF check; assert user created and tokens returned
    - _Implements: Req 5.1–5.6_

  - [ ]* 32.4 Write integration test for logout-all and session management
    - Logout-all invalidates all sessions and blocklists all JTIs
    - Subsequent requests with old access token return HTTP 401
    - _Implements: Req 8.5, Req 8.6_


### Phase 12: Deployment

- [ ] 33. Implement health endpoints and graceful shutdown
  - Create `GET /health/live` (liveness probe): returns HTTP 200 if process is running; no dependency checks
  - Create `GET /health/ready` (readiness probe): checks MySQL primary connectivity, Redis connectivity, and encryption key validation; returns HTTP 200 only when all pass; returns HTTP 503 with failing component details otherwise
  - Implement graceful shutdown in `main.ts`: on SIGTERM/SIGINT, stop accepting new connections, wait up to 25s for in-flight requests to complete, close DB pool, close Redis connections, flush BullMQ workers
  - Implement startup validation: run `validateEncryptionKeys()` (Section 7.5) and migration checksum verification before accepting traffic
  - _Implements: Req 13.6 (startup checks), Req 15_

  - [ ]* 33.1 Write unit tests for health endpoints
    - Liveness always returns 200
    - Readiness returns 503 when MySQL is unreachable
    - Readiness returns 503 when Redis is unreachable
    - Readiness returns 503 when encryption roundtrip fails
    - _Implements: Req 13.1 (startup validation)_

- [ ] 34. Create Kubernetes deployment manifests
  - Create `k8s/deployment.yaml`: `Deployment` with `replicas: 2`, resource requests/limits (`cpu: 500m/2000m`, `memory: 512Mi/2Gi`), liveness probe (`/health/live`, initialDelaySeconds: 10), readiness probe (`/health/ready`, initialDelaySeconds: 15), `terminationGracePeriodSeconds: 30`, env vars from `ConfigMap` and `Secret`
  - Create `k8s/hpa.yaml`: `HorizontalPodAutoscaler` scaling on CPU (70% threshold) and custom metric `uicp_request_queue_depth`; `minReplicas: 2`, `maxReplicas: 20`
  - Create `k8s/pdb.yaml`: `PodDisruptionBudget` with `minAvailable: 1` to ensure HA during rolling updates
  - Create `k8s/service.yaml`: `Service` of type `ClusterIP` for HTTP (3000) and gRPC (5000) ports
  - Create `k8s/configmap.yaml`: non-secret configuration (log level, DB adapter, Redis cluster nodes, OTel endpoint)
  - Create `k8s/secret.yaml` (template): placeholder for `ENCRYPT_KEY_*`, `JWT_PRIVATE_KEY`, `DB_PASSWORD`, `REDIS_PASSWORD`, `PEPPER` — actual values managed by external secrets operator
  - _Implements: Req 1 (multi-replica), Req 15 (HA)_

- [ ] 35. Final checkpoint — Ensure all tests pass
  - Run full test suite including property-based tests, unit tests, and integration tests
  - Verify TypeScript compiles with zero errors
  - Verify all 20 correctness properties pass
  - Verify Docker image builds successfully
  - Ensure all tests pass, ask the user if questions arise.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP; all 20 property-based tests are marked optional per workflow convention but are strongly recommended for a security-critical system
- Each task references specific requirements for traceability
- Checkpoints (tasks 24 and 35) ensure incremental validation at phase boundaries
- Property tests use `fast-check` with the custom arbitraries defined in Section 14.1 of the design
- Integration tests require real MySQL 8.0 and Redis 7+ via test containers (`testcontainers` npm package)
- The DB adapter pattern (Section 16.1) means all MySQL adapters have a PostgreSQL mirror — implement MySQL first, then mirror for Postgres if needed
- All 20 correctness properties from Section 15 of the design are covered by explicit property-based test sub-tasks distributed across the phases where the relevant component is implemented

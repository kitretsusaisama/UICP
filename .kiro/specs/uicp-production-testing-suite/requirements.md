# Requirements Document

## Introduction

This document specifies the production-grade testing suite for the UICP (Unified Identity Control Plane) — a multi-tenant distributed identity runtime built with NestJS, MySQL, Redis, and BullMQ. The platform is not a simple auth API: it is a distributed identity runtime, multi-tenant auth infrastructure, provider-orchestrated communication system, session lineage platform, replay-sensitive auth runtime, and tenant-isolated security platform.

The testing suite must validate production runtime correctness across 15 primary objectives: authentication correctness, session lifecycle integrity, refresh token replay prevention, multi-device session consistency, tenant isolation guarantees, RBAC enforcement, OTP lifecycle correctness, queue processing consistency, provider failover correctness, tenant-specific provider routing, tenant-specific API key correctness, concurrency safety, state transition correctness, distributed queue correctness, and communication isolation.

The suite is organized into eight execution phases that run in strict order: Contract → Integration → Providers → Queues → Security → Concurrency → Regression → Performance. Execution stops on the first failure.

## Glossary

- **Auth_Runtime**: The NestJS application layer responsible for issuing, validating, and revoking JWT access and refresh tokens.
- **Session_Runtime**: The Redis-backed session store managed by `SessionService`, tracking per-user, per-tenant session state.
- **Replay_Guard**: The distributed mechanism (Redis atomic operations + refresh token family tracking) that prevents refresh token reuse.
- **Tenant_Isolation_Layer**: The set of cache key namespacing, database row-level scoping, and provider routing rules that prevent cross-tenant data leakage.
- **OTP_Runtime**: The `OtpService` and `NotificationDispatcherService` pipeline responsible for generating, storing, delivering, and consuming one-time passwords.
- **Provider_Router**: The `ProviderRoutingService` and `NotificationDispatcherService` that resolve tenant-specific SMS/email providers and execute fallback chains.
- **Queue_Runtime**: The BullMQ-backed job queue and `OutboxRelayWorker` responsible for at-least-once delivery of domain events and OTP dispatch jobs.
- **RBAC_Engine**: The `RuntimeAuthorizationService` that evaluates role and permission assignments scoped to a tenant.
- **Token_Service**: The `TokenService` responsible for minting, signing (RS256), parsing, and validating JWT access and refresh tokens.
- **Refresh_Token_Family**: A lineage group of refresh tokens tracked in `refresh_token_families`. When any token in a family is replayed, the entire family is revoked.
- **Tenant**: An isolated organizational unit with its own users, sessions, providers, API keys, OTP templates, retry rules, and security policies.
- **Provider_Config**: A row in `tenant_sms_providers` or `tenant_email_providers` containing tenant-scoped credentials, sender IDs, and routing priority.
- **Circuit_Breaker**: The per-tenant, per-provider state machine (CLOSED → OPEN → HALF_OPEN) that stops routing to a failing provider.
- **Outbox_Event**: A row in `outbox_events` representing a domain event pending publication to BullMQ, with status PENDING → PUBLISHED or DLQ.
- **Dead_Letter_Queue**: The terminal failure state for outbox events and BullMQ jobs that have exhausted all retry attempts.
- **PBT**: Property-Based Testing using the `fast-check` library already present in the project.
- **JTI**: JWT ID — the unique identifier (`jti` claim) of a JWT token, used for blocklisting.
- **Family_ID**: The `fid` claim in a refresh token, linking it to a `refresh_token_families` row.

## Requirements

### Requirement 1: Authentication Correctness

**User Story:** As a security engineer, I want the Auth_Runtime to produce structurally and semantically correct JWT tokens for every valid login, so that downstream services can trust token claims without additional validation.

#### Acceptance Criteria

1. WHEN the Token_Service mints an access token, THE Token_Service SHALL produce a JWT with `type: "access"`, a non-empty `jti`, a `tid` matching the requesting tenant, a `sub` matching the principal ID, and `exp` set to `iat + JWT_ACCESS_TOKEN_TTL_S`.
2. WHEN the Token_Service mints a refresh token, THE Token_Service SHALL produce a JWT with `type: "refresh"`, a non-empty `jti`, a `fid` matching the token family ID, and `exp` set to `iat + JWT_REFRESH_TOKEN_TTL_S`.
3. FOR ALL valid access tokens minted by the Token_Service, parsing the token with `parseAccessToken` SHALL return a payload structurally equal to the original minted payload (round-trip property).
4. WHEN an access token is parsed with `parseAccessToken`, THE Token_Service SHALL reject tokens signed with any key other than the configured RS256 private key by throwing a verification error.
5. WHEN an access token is parsed with `parseAccessToken`, THE Token_Service SHALL reject tokens where the `type` claim is not `"access"` by throwing `TOKEN_TYPE_MISMATCH`.
6. WHEN an access token is parsed with `parseAccessToken`, THE Token_Service SHALL reject tokens where the `aud` claim does not match `JWT_AUDIENCE` by throwing a verification error.
7. WHEN `validateAccessToken` is called with a blocklisted JTI, THE Token_Service SHALL throw `TOKEN_BLOCKLISTED` without performing any other side effects.
8. WHEN an access token has expired (current time > `exp`), THE Token_Service SHALL reject the token by throwing a verification error.

---

### Requirement 2: Session Lifecycle Integrity

**User Story:** As a platform operator, I want the Session_Runtime to enforce correct state transitions and TTL semantics, so that sessions cannot be used after expiry or revocation.

#### Acceptance Criteria

1. WHEN a session is created, THE Session_Runtime SHALL assign an initial status of `created` and store the session in Redis with a TTL equal to `SESSION_TTL_S`.
2. WHEN MFA is required for a session, THE Session_Runtime SHALL transition the session status from `created` to `mfa_pending` and SHALL NOT allow the session to reach `active` until MFA is verified.
3. WHEN a session is invalidated, THE Session_Runtime SHALL set the session status to `revoked` and SHALL NOT return the session in subsequent `findById` calls.
4. WHEN `invalidateAll` is called for a user, THE Session_Runtime SHALL revoke all active sessions for that user within the same tenant and SHALL NOT affect sessions belonging to other tenants.
5. WHEN `extendTtl` is called on an active session, THE Session_Runtime SHALL reset the Redis TTL to `SESSION_TTL_S` without changing the session status.
6. FOR ALL session status transitions, THE Session_Runtime SHALL enforce that status only moves forward in the sequence `created → mfa_pending → active → (expired | revoked)` and SHALL NOT allow backward transitions (invariant property).
7. WHEN the maximum sessions per user (`max_sessions_per_user`) is reached, THE Session_Runtime SHALL evict the oldest session (LRU) before creating a new one, ensuring the active session count never exceeds `max_sessions_per_user`.
8. WHEN a trusted device fingerprint is added for a user, THE Session_Runtime SHALL store it in a tenant-scoped Redis key and SHALL NOT make it accessible from a different tenant's key namespace.

---

### Requirement 3: Refresh Token Replay Prevention

**User Story:** As a security engineer, I want the Replay_Guard to ensure that a consumed refresh token can never be used again, so that stolen tokens cannot be replayed to obtain new access tokens.

#### Acceptance Criteria

1. WHEN a refresh token is consumed to rotate a token pair, THE Replay_Guard SHALL mark the consumed token as revoked and issue a new refresh token with a new JTI in the same family.
2. WHEN a previously consumed refresh token is submitted again, THE Replay_Guard SHALL reject the request and SHALL revoke the entire Refresh_Token_Family associated with that token (family compromise detection).
3. FOR ALL refresh tokens, the property `consume(T) succeeds ⟹ consume(T) again throws REPLAY_DETECTED` SHALL hold for any token T (single-use invariant).
4. WHEN two concurrent requests submit the same refresh token simultaneously, THE Replay_Guard SHALL allow exactly one request to succeed and SHALL reject the other with a replay error (deterministic concurrency safety).
5. WHEN a Refresh_Token_Family is revoked due to replay detection, THE Replay_Guard SHALL invalidate all tokens in that family, including any tokens issued after the replayed token.
6. WHEN a refresh token with an expired `exp` claim is submitted, THE Replay_Guard SHALL reject the request with a token expiry error before performing any family lookup.

---

### Requirement 4: Multi-Device Session Consistency

**User Story:** As a user, I want my sessions across multiple devices to be tracked independently and consistently, so that logging out on one device does not unexpectedly affect other devices unless I choose logout-all.

#### Acceptance Criteria

1. WHEN a user creates sessions from N distinct devices (N ≤ `max_sessions_per_user`), THE Session_Runtime SHALL maintain N independent session records, each with a distinct session ID and device fingerprint.
2. WHEN a single session is invalidated, THE Session_Runtime SHALL revoke only that session and SHALL leave all other sessions for the same user in their current state.
3. WHEN `invalidateAll` is called, THE Session_Runtime SHALL revoke all sessions for the user within the tenant and the `listByUser` call SHALL return an empty list.
4. FOR ALL users with K active sessions (K ≤ `max_sessions_per_user`), the invariant `listByUser(userId, tenantId).length ≤ max_sessions_per_user` SHALL hold after any sequence of create and invalidate operations.
5. WHEN a new session is created and the user already has `max_sessions_per_user` active sessions, THE Session_Runtime SHALL evict exactly one session (the oldest by creation time) before creating the new session, maintaining the count invariant.

---

### Requirement 5: Tenant Isolation Guarantees

**User Story:** As a platform operator, I want the Tenant_Isolation_Layer to guarantee that no data, session, OTP, provider credential, or cache entry from Tenant A is ever accessible from Tenant B's context, so that multi-tenant security boundaries are never violated.

#### Acceptance Criteria

1. FOR ALL Redis cache keys written by the Session_Runtime, THE Tenant_Isolation_Layer SHALL include the tenant ID as a namespace prefix in every key, ensuring keys from different tenants are disjoint.
2. WHEN Tenant A's cache is invalidated, THE Tenant_Isolation_Layer SHALL NOT affect any cache entries belonging to Tenant B (cache invalidation isolation invariant).
3. WHEN a session lookup is performed with Tenant A's tenant ID, THE Session_Runtime SHALL NOT return sessions that were created under Tenant B's tenant ID, even if the user ID is identical.
4. WHEN an OTP is stored for a user in Tenant A, THE OTP_Runtime SHALL NOT allow that OTP to be verified in the context of Tenant B.
5. WHEN provider routing is resolved for Tenant A, THE Provider_Router SHALL use only Provider_Config rows where `tenant_id` matches Tenant A's ID and SHALL NOT use any Provider_Config belonging to Tenant B.
6. WHEN Tenant A sends 1000 OTP dispatch jobs and Tenant B sends 10 OTP dispatch jobs concurrently, THE Queue_Runtime SHALL process Tenant B's jobs without being blocked by Tenant A's volume (queue fairness isolation).
7. WHEN a JWT access token issued for Tenant A is submitted to an endpoint scoped to Tenant B, THE Auth_Runtime SHALL reject the request because the `tid` claim does not match the target tenant.

---

### Requirement 6: RBAC Enforcement

**User Story:** As a platform operator, I want the RBAC_Engine to enforce role and permission assignments correctly and consistently, so that users can only access resources they are explicitly authorized for within their tenant.

#### Acceptance Criteria

1. WHEN a user has role R assigned in Tenant T, THE RBAC_Engine SHALL grant access to all resources covered by the permissions associated with role R in Tenant T.
2. WHEN a user does not have role R assigned in Tenant T, THE RBAC_Engine SHALL deny access to resources that require role R, returning an authorization error.
3. FOR ALL permission checks, the result SHALL be deterministic: given the same user ID, tenant ID, resource, and action, the RBAC_Engine SHALL always return the same authorization decision (idempotence property).
4. WHEN a role is assigned in Tenant A, THE RBAC_Engine SHALL NOT grant that role's permissions to the same user in Tenant B (role assignment is tenant-scoped).
5. WHEN a permission is checked for a user with multiple roles, THE RBAC_Engine SHALL grant access if ANY of the user's roles includes the required permission (union semantics).
6. WHEN a role is revoked from a user, THE RBAC_Engine SHALL deny access to resources that required that role on all subsequent permission checks.

---

### Requirement 7: OTP Lifecycle Correctness

**User Story:** As a security engineer, I want the OTP_Runtime to enforce single-use, expiry, and timing-safe verification semantics, so that OTP codes cannot be replayed, brute-forced, or used after expiry.

#### Acceptance Criteria

1. WHEN an OTP code is generated, THE OTP_Runtime SHALL produce a cryptographically random 6-digit string using `crypto.randomInt`, uniformly distributed in the range `[000000, 999999]`.
2. WHEN an OTP code is stored, THE OTP_Runtime SHALL write it to Redis with a TTL equal to `OTP_TTL_S` (default 300 seconds).
3. WHEN `verifyAndConsume` is called with the correct code for the first time, THE OTP_Runtime SHALL succeed and atomically delete the code from Redis.
4. FOR ALL valid OTP codes, the property `verifyAndConsume(C) succeeds ⟹ verifyAndConsume(C) again throws OTP_ALREADY_USED` SHALL hold (single-use invariant — round-trip property).
5. WHEN `verifyAndConsume` is called after the OTP TTL has elapsed, THE OTP_Runtime SHALL throw `OTP_EXPIRED`.
6. WHEN `verifyAndConsume` is called with an incorrect code, THE OTP_Runtime SHALL throw `INVALID_OTP` without consuming the stored code.
7. WHEN `verifyAndConsume` is called with an incorrect code, THE OTP_Runtime SHALL use timing-safe comparison so that the response time does not leak information about the stored code.
8. WHEN two concurrent `verifyAndConsume` calls are made with the same correct code, THE OTP_Runtime SHALL allow exactly one to succeed and SHALL return `OTP_ALREADY_USED` for the other (atomic single-use under concurrency).
9. WHEN an OTP is stored for purpose `MFA` for a user in Tenant A, THE OTP_Runtime SHALL NOT allow that code to be verified for purpose `IDENTITY_VERIFICATION` or for any user in Tenant B (purpose and tenant isolation).

---

### Requirement 8: Queue Processing Consistency

**User Story:** As a platform operator, I want the Queue_Runtime to guarantee at-least-once delivery of all outbox events and OTP dispatch jobs, with dead-letter handling for permanently failed jobs, so that no message is silently lost.

#### Acceptance Criteria

1. FOR ALL outbox events with status `PENDING`, THE Queue_Runtime SHALL eventually transition each event to either `PUBLISHED` or `DLQ` — no event SHALL remain in `PENDING` or `FAILED` status indefinitely (at-least-once delivery invariant).
2. WHEN an outbox event publish attempt fails, THE Queue_Runtime SHALL retry the event up to `MAX_ATTEMPTS` (5) times before moving it to `DLQ`.
3. WHEN an outbox event has been retried `MAX_ATTEMPTS` times without success, THE Queue_Runtime SHALL move it to `DLQ` status and SHALL NOT retry it further.
4. FOR ALL outbox events, the property `drain(events) ⟹ all events in {PUBLISHED, DLQ}` SHALL hold regardless of the publish failure probability (terminal state invariant — property test).
5. WHEN an OTP dispatch job is enqueued for Tenant A and an OTP dispatch job is enqueued for Tenant B, THE Queue_Runtime SHALL process both jobs independently without one blocking the other.
6. WHEN a BullMQ job fails permanently and is moved to the dead-letter queue, THE Queue_Runtime SHALL preserve the job payload and error details for inspection.
7. WHEN the same outbox event is processed twice (at-least-once delivery), THE Queue_Runtime SHALL produce the same observable outcome as processing it once (idempotent processing).

---

### Requirement 9: Provider Failover Correctness

**User Story:** As a platform operator, I want the Provider_Router to automatically fail over to the next available provider when the primary provider fails, so that OTP delivery continues without manual intervention.

#### Acceptance Criteria

1. WHEN the primary provider for a tenant fails with an error, THE Provider_Router SHALL attempt delivery using the next provider in the fallback chain without returning an error to the caller.
2. WHEN all providers in the fallback chain fail, THE Provider_Router SHALL throw `OTP_DELIVERY_FAILED` with the last error message.
3. WHEN a provider succeeds after one or more fallback attempts, THE Provider_Router SHALL record exactly one successful delivery attempt and SHALL NOT attempt further providers.
4. FOR ALL delivery attempts, the property `exactly one provider succeeds ⟹ exactly one delivery is recorded` SHALL hold regardless of which provider in the chain succeeds (idempotent delivery invariant).
5. WHEN a provider's Circuit_Breaker is in `OPEN` state, THE Provider_Router SHALL skip that provider and proceed to the next in the fallback chain without attempting a call.
6. WHEN a provider fails N consecutive times (where N equals the circuit breaker threshold), THE Provider_Router SHALL transition that provider's Circuit_Breaker from `CLOSED` to `OPEN`.
7. WHEN a Circuit_Breaker is in `HALF_OPEN` state and the probe request succeeds, THE Provider_Router SHALL transition the Circuit_Breaker back to `CLOSED`.

---

### Requirement 10: Tenant-Specific Provider Routing

**User Story:** As a platform operator, I want the Provider_Router to resolve provider configurations exclusively from the requesting tenant's Provider_Config rows, so that Tenant A's SMS provider is never used to deliver Tenant B's messages.

#### Acceptance Criteria

1. WHEN the Provider_Router resolves a route for Tenant A, THE Provider_Router SHALL select only Provider_Config rows where `tenant_id` equals Tenant A's ID.
2. WHEN Tenant A is configured with MSG91 as its primary SMS provider and Tenant B is configured with a different provider, THE Provider_Router SHALL use MSG91 for Tenant A's deliveries and SHALL NOT use MSG91 for Tenant B's deliveries unless Tenant B also explicitly configures MSG91.
3. FOR ALL provider resolution calls, the property `resolve(tenantId_A) ∩ resolve(tenantId_B) = ∅` SHALL hold when Tenant A and Tenant B have disjoint provider configurations (provider set isolation invariant).
4. WHEN a tenant has no Provider_Config rows for a given channel, THE Provider_Router SHALL fall back to the global default provider configuration and SHALL NOT use another tenant's provider configuration.
5. WHEN Tenant A's provider configuration is updated, THE Provider_Router SHALL use the updated configuration for all subsequent routing decisions for Tenant A without affecting Tenant B's routing.

---

### Requirement 11: Tenant-Specific API Key Correctness

**User Story:** As a security engineer, I want each tenant's provider API keys to be used exclusively for that tenant's outbound communications, so that API key leakage between tenants is impossible.

#### Acceptance Criteria

1. WHEN the Provider_Router dispatches an SMS for Tenant A, THE Provider_Router SHALL use only the API key stored in Tenant A's Provider_Config row and SHALL NOT use any API key from Tenant B's Provider_Config.
2. WHEN the Provider_Router dispatches an email for Tenant A, THE Provider_Router SHALL use only the sender address and credentials from Tenant A's `tenant_email_providers` row.
3. WHEN Tenant A's sender ID is `APPA` and Tenant B's sender ID is `APPB`, THE Provider_Router SHALL use `APPA` for all of Tenant A's SMS deliveries and `APPB` for all of Tenant B's SMS deliveries, with no cross-contamination.
4. FOR ALL provider dispatch calls, the property `dispatch(tenantId, message).senderConfig = tenantProviderConfig(tenantId).senderConfig` SHALL hold (sender config invariant).
5. WHEN a provider call is made, THE Provider_Router SHALL NOT include credentials or sender IDs from any tenant other than the one that initiated the request.

---

### Requirement 12: Concurrency Safety

**User Story:** As a platform operator, I want all concurrent operations on shared state (refresh tokens, OTP codes, sessions) to be safe under race conditions, so that the system produces correct results even under high concurrency.

#### Acceptance Criteria

1. WHEN N concurrent requests attempt to consume the same refresh token simultaneously (N ≥ 2), THE Replay_Guard SHALL allow exactly one request to succeed and SHALL return a replay error for all remaining N-1 requests.
2. WHEN N concurrent requests attempt to verify the same OTP code simultaneously (N ≥ 2), THE OTP_Runtime SHALL allow exactly one request to succeed and SHALL return `OTP_ALREADY_USED` for all remaining N-1 requests.
3. WHEN N concurrent session creation requests are made for the same user who is at `max_sessions_per_user`, THE Session_Runtime SHALL allow temporary violation of the count invariant during the concurrent create and evict operations, and SHALL restore the invariant to `count ≤ max_sessions_per_user` after all concurrent operations complete.
4. WHEN a distributed lock is acquired for a resource, THE Distributed_Lock_Service SHALL prevent any other process from acquiring the same lock until the first lock is released or expires.
5. WHEN a cache invalidation is performed for Tenant A's data concurrently with a read for Tenant A's data, THE Tenant_Isolation_Layer SHALL ensure the read either returns the pre-invalidation value or the post-invalidation value, never a corrupted intermediate state.

---

### Requirement 13: State Transition Correctness

**User Story:** As a platform operator, I want all domain state machines (OTP flows, sessions, outbox events, circuit breakers) to enforce valid transitions only, so that the system never enters an inconsistent state.

#### Acceptance Criteria

1. FOR ALL OTP flow records, the status SHALL only transition through the sequence `created → queued → sent → (verified | expired | failed | replayed)` and SHALL NOT transition backward or skip states.
2. FOR ALL session records, the status SHALL only transition through the sequence `created → mfa_pending → active → (expired | revoked)` and SHALL NOT transition backward.
3. FOR ALL outbox event records, the status SHALL only transition through the sequence `PENDING → (PUBLISHED | FAILED → DLQ)` and SHALL NOT transition from `PUBLISHED` or `DLQ` to any other status.
4. FOR ALL Circuit_Breaker state machines, the state SHALL only transition through `CLOSED → OPEN → HALF_OPEN → CLOSED` and SHALL NOT skip states or transition backward from `CLOSED` to `HALF_OPEN`.
5. WHEN any state transition is attempted that violates the defined state machine, THE system SHALL reject the transition and preserve the current state without side effects; no additional safeguards such as logging or fallback states are required beyond rejection and state preservation.

---

### Requirement 14: Distributed Queue Correctness

**User Story:** As a platform operator, I want the Queue_Runtime to process jobs correctly under distributed conditions, including partial failures, retries, and concurrent workers, so that no job is lost or processed in a way that corrupts system state.

#### Acceptance Criteria

1. WHEN an outbox event is published to BullMQ, THE Queue_Runtime SHALL record the event as `PUBLISHED` in the outbox table only after the BullMQ enqueue operation succeeds.
2. WHEN a BullMQ enqueue operation fails after the outbox event has been written, THE Queue_Runtime SHALL leave the event in `FAILED` status for retry and SHALL NOT mark it as `PUBLISHED`.
3. WHEN a provider creation transaction succeeds but the subsequent queue registration fails, THE system SHALL perform a full rollback of the provider creation, leaving no partial state in the database.
4. FOR ALL BullMQ job payloads, the property `process(job) = process(process(job))` SHALL hold — processing the same job twice SHALL produce the same observable outcome as processing it once (idempotent job processing).
5. WHEN the Queue_Runtime processes an OTP dispatch job, THE Queue_Runtime SHALL record a `communication_delivery_attempts` row with the correct `tenant_id`, `provider_name`, and `idempotency_key` before attempting delivery.

---

### Requirement 15: Communication Isolation

**User Story:** As a security engineer, I want the OTP_Runtime and Provider_Router to guarantee that sender IDs, domain names, email addresses, and provider credentials from one tenant never appear in another tenant's outbound communications, so that brand and security isolation is maintained.

#### Acceptance Criteria

1. WHEN an OTP email is sent for Tenant A, THE OTP_Runtime SHALL use only the `from_email` and `from_name` configured in Tenant A's `tenant_email_providers` row and SHALL NOT use any sender address from Tenant B's configuration.
2. WHEN an OTP SMS is sent for Tenant A, THE OTP_Runtime SHALL use only the `sender_id` configured in Tenant A's `tenant_sms_providers` row and SHALL NOT use any sender ID from Tenant B's configuration.
3. FOR ALL delivery attempts recorded in `communication_delivery_attempts`, the `tenant_id` column SHALL match the tenant that initiated the OTP request (delivery lineage invariant).
4. WHEN a provider webhook event is received, THE Provider_Router SHALL associate the event with the correct tenant based on the webhook signature and SHALL NOT process it in the context of a different tenant.
5. WHEN Tenant A's verified sender domain is `mail.tenant-a.com` and Tenant B's verified sender domain is `mail.tenant-b.com`, THE OTP_Runtime SHALL use `mail.tenant-a.com` for Tenant A's emails and `mail.tenant-b.com` for Tenant B's emails, with no domain leakage between tenants.
6. WHEN a communication template is resolved for Tenant A, THE OTP_Runtime SHALL use only templates where `tenant_id` matches Tenant A's ID and SHALL NOT use templates belonging to Tenant B.

---

### Requirement 16: Test Infrastructure and Setup

**User Story:** As a developer, I want the test suite to have reliable, isolated infrastructure setup and teardown, so that tests are reproducible, do not interfere with each other, and can run in CI without external dependencies.

#### Acceptance Criteria

1. THE Test_Infrastructure SHALL provide a `TestApp` factory that bootstrarates a full NestJS application context with in-memory or containerized MySQL, Redis, and BullMQ instances for integration tests.
2. THE Test_Infrastructure SHALL provide tenant fixture factories that create isolated tenant records with distinct provider configurations, API keys, and sender IDs for use across all test categories.
3. THE Test_Infrastructure SHALL provide fake provider implementations (`FakeMsg91`, `FakeResend`, `FakeMaileroo`) that record all dispatch calls with their tenant context, enabling assertion of provider isolation.
4. WHEN a test suite completes normally, THE Test_Infrastructure SHALL clean up all created tenants, sessions, OTP records, and queue jobs to prevent state leakage between test suites; IF the test suite crashes or is interrupted, THE Test_Infrastructure SHALL leave resources uncleaned and SHALL NOT attempt cleanup on abnormal termination.
5. THE Test_Infrastructure SHALL support the execution order Contract → Integration → Providers → Queues → Security → Concurrency → Regression → Performance, stopping on the first suite failure.
6. THE Test_Infrastructure SHALL provide helpers for generating valid JWT tokens, refresh token families, and session records for use in security and concurrency tests without requiring a running HTTP server.

---

### Requirement 17: Regression Coverage

**User Story:** As a developer, I want every discovered production auth bug to be captured as a permanent regression test, so that fixed bugs can never silently reappear in future releases.

#### Acceptance Criteria

1. WHEN a production bug is discovered in the Auth_Runtime, THE Regression_Suite SHALL contain a test that reproduces the exact failure condition before the fix is applied.
2. WHEN a production bug is fixed, THE Regression_Suite SHALL contain a test that verifies the fix is in place and the failure condition no longer occurs.
3. THE Regression_Suite SHALL cover at minimum: OTP replay via race condition, refresh token family not revoked on replay detection, cross-tenant session lookup returning wrong tenant's data, and provider credential leakage between tenants — these four tests SHALL be present regardless of whether the corresponding bugs have been discovered in production.
4. WHEN a regression test is added, THE Regression_Suite SHALL include a comment referencing the original bug report or incident identifier so the test's purpose is traceable.

---

### Requirement 18: Coverage Targets

**User Story:** As a platform operator, I want the test suite to achieve defined coverage targets for each critical runtime component, so that the risk of undetected defects in production is minimized.

#### Acceptance Criteria

1. THE Auth_Runtime test coverage SHALL reach 100% branch coverage across `TokenService` mint, parse, validate, and rotation paths.
2. THE Session_Runtime test coverage SHALL reach 100% branch coverage across `SessionService` create, invalidate, invalidateAll, extendTtl, and trusted device paths.
3. THE Replay_Guard test coverage SHALL reach 100% branch coverage across all refresh token consumption, family revocation, and concurrent replay paths.
4. THE Tenant_Isolation_Layer test coverage SHALL reach 100% branch coverage across all cache key construction, session scoping, OTP scoping, and provider routing paths.
5. THE OTP_Runtime test coverage SHALL reach 100% branch coverage across `OtpService` generate, store, verifyAndConsume, and timing-safe comparison paths.
6. THE Provider_Router test coverage SHALL reach 100% branch coverage across provider resolution, fallback chain execution, and circuit breaker state transition paths.
7. THE Queue_Runtime test coverage SHALL reach 95% branch coverage across `OutboxRelayWorker` poll, publish, retry, and DLQ paths.
8. THE RBAC_Engine test coverage SHALL reach 95% branch coverage across permission check, role assignment, and tenant-scoped authorization paths.
9. THE JWT validation paths in `TokenService` SHALL reach 100% branch coverage including algorithm rejection, audience mismatch, issuer mismatch, expiry, and blocklist checks.

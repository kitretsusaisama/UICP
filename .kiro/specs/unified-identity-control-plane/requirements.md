# Requirements Document

## Introduction

The Unified Identity Control Plane (UICP) is a production-grade, multi-tenant identity and access management platform built with TypeScript and NestJS. It provides authentication, authorization, session management, and security operations for enterprise-scale deployments using Hexagonal Architecture, CQRS, Event Sourcing, and the Transactional Outbox Pattern.

The system supports email/phone credential authentication, OAuth 2.0 social login (Google, GitHub, Apple, Microsoft), MFA via OTP, JWT-based token lifecycle management, Attribute-Based Access Control (ABAC), Role-Based Access Control (RBAC), User and Entity Behavior Analytics (UEBA), distributed session management, field-level AES-256-GCM encryption, immutable audit logging, and a real-time SOC dashboard — all with strict multi-tenant data isolation and zero-trust security.

## Glossary

- **UICP**: Unified Identity Control Plane — the system described in this document.
- **Tenant**: An isolated organizational unit within the UICP. All user data is partitioned by tenant.
- **TenantId**: A UUID v4 value object uniquely identifying a tenant.
- **UserId**: A UUID v4 value object uniquely identifying a user within a tenant.
- **IdentityId**: A UUID v4 value object uniquely identifying a linked identity (email, phone, or OAuth).
- **SessionId**: A UUID v4 value object uniquely identifying an active session.
- **TokenId**: A UUID v4 used as the JWT `jti` claim for blocklist lookups.
- **User_Aggregate**: The domain aggregate root representing a user and their linked identities, with a state machine (PENDING → ACTIVE → SUSPENDED → DELETED).
- **Identity**: An entity within the User_Aggregate representing a verifiable credential link (email, phone, or OAuth provider).
- **Session**: A domain aggregate representing an authenticated session stored in Redis.
- **Credential**: A hashed password record associated with a user.
- **Access_Token**: A short-lived RS256-signed JWT (15-minute TTL) carrying embedded roles and permissions.
- **Refresh_Token**: A longer-lived RS256-signed JWT (7-day TTL) used to rotate Access_Tokens.
- **Token_Family**: A group of Refresh_Tokens sharing the same `fid` claim, used for reuse-detection revocation.
- **OTP**: A one-time password code delivered via email or SMS for MFA or identity verification.
- **ABAC**: Attribute-Based Access Control — a policy engine that evaluates subject, resource, and action conditions expressed in a DSL.
- **ABAC_Policy**: A domain object containing subject, resource, and action conditions in the ABAC DSL, with an effect (ALLOW or DENY) and a priority.
- **RBAC**: Role-Based Access Control — roles assigned to users, with permissions assigned to roles.
- **UEBA_Engine**: The User and Entity Behavior Analytics engine that computes a composite threat score from velocity, geo, device, and credential-stuffing signals.
- **Threat_Score**: A floating-point value in [0.0, 1.0] representing the risk level of an authentication event.
- **Kill_Chain_Stage**: An enumeration of attack stages: RECONNAISSANCE, INITIAL_ACCESS, CREDENTIAL_ACCESS, LATERAL_MOVEMENT, ACCOUNT_TAKEOVER.
- **SOC_Alert**: An immutable record of a detected threat event, with a workflow state (OPEN → ACKNOWLEDGED → RESOLVED | FALSE_POSITIVE).
- **Outbox_Event**: A record in the `outbox_events` table written atomically with domain data changes, relayed to BullMQ by the OutboxRelayWorker.
- **Domain_Event**: An immutable record in the `domain_events` event store representing a state change to an aggregate.
- **Encryption_Service**: The infrastructure adapter implementing AES-256-GCM encryption with HKDF key derivation.
- **Encryption_Context**: A named context (e.g., IDENTITY_VALUE, USER_PII) used to derive a tenant-specific encryption key via HKDF.
- **HMAC**: A keyed hash used for searchable encryption — allows equality lookups on encrypted fields without decryption.
- **Distributed_Lock**: A Redis-based mutual exclusion primitive implemented via SET NX PX with Lua-script release.
- **Idempotency_Key**: A client-supplied UUID in the `X-Idempotency-Key` header; responses are cached for 24 hours to enable safe retries.
- **CLS**: Continuation Local Storage — AsyncLocalStorage-based context propagation carrying `requestId`, `tenantId`, `userId`, `traceId`, and `sessionId` through the entire async call stack.
- **Outbox_Relay_Worker**: A BullMQ worker that polls the `outbox_events` table using `SELECT ... FOR UPDATE SKIP LOCKED` and publishes events to BullMQ queues.
- **Circuit_Breaker**: A resilience pattern that trips open after a threshold of failures, preventing cascading failures to downstream dependencies.
- **Bcrypt_Rounds**: The adaptive work factor for bcrypt password hashing, calibrated to target a p95 hash time of 200ms.
- **JWKS**: JSON Web Key Set — the public key endpoint (`/.well-known/jwks.json`) used by downstream services to verify Access_Tokens.
- **GeoIP_DB**: The local MaxMind GeoLite2 database used for impossible travel detection.
- **Rate_Limiter**: A token-bucket rate limiter enforcing per-IP and per-user request limits.
- **Haversine_Distance**: The great-circle distance between two geographic coordinates, used by the UEBA geo analyzer.
- **Value_Object**: An immutable domain primitive (Email, PhoneNumber, RawPassword, TenantId, etc.) that enforces its own invariants on construction.
- **DB_Adapter**: The infrastructure abstraction layer that allows swapping between MySQL and PostgreSQL without changing application code.
- **HPA**: Horizontal Pod Autoscaler — Kubernetes resource that scales pod replicas based on CPU and custom metrics.
- **PDB**: PodDisruptionBudget — Kubernetes resource ensuring minimum available replicas during disruptions.


## Requirements

### Requirement 1: Multi-Tenant Identity Management

**User Story:** As a platform operator, I want strict tenant isolation so that user data from one tenant is never accessible to another tenant.

#### Acceptance Criteria

1. THE UICP SHALL enforce `tenant_id` as a mandatory predicate on every database query that accesses user, identity, session, credential, or audit data.
2. WHEN a repository method is invoked with a TenantId, THE Repository SHALL include `WHERE tenant_id = ?` in all generated SQL statements.
3. IF a query with `tenantId=A` is executed, THEN THE Repository SHALL return zero rows belonging to `tenantId=B` even when row IDs are known.
4. THE Encryption_Service SHALL derive per-tenant encryption keys using `HKDF(masterKey, tenantId || context)` so that a key compromise for one context cannot decrypt another tenant's data.
5. THE UICP SHALL enforce control plane / data plane separation so that tenant provisioning operations never join across tenant data tables.
6. WHEN a JWT contains `tid=A` and the request carries `X-Tenant-ID=B`, THE TenantGuard SHALL reject the request with HTTP 403.

---

### Requirement 2: Email and Phone Credential Authentication — Signup

**User Story:** As a new user, I want to register with my email or phone number so that I can create an account and access the platform.

#### Acceptance Criteria

1. WHEN a user submits a valid email address and password to `POST /auth/signup`, THE UICP SHALL create a User_Aggregate in PENDING status, link an unverified email Identity, and dispatch an OTP to the provided email address.
2. WHEN a user submits a valid E.164 phone number and password to `POST /auth/signup`, THE UICP SHALL create a User_Aggregate in PENDING status, link an unverified phone Identity, and dispatch an OTP via SMS.
3. IF a signup request is submitted with an email or phone that already exists for the same tenant, THEN THE UICP SHALL return HTTP 409 with error code `IDENTITY_ALREADY_EXISTS`.
4. THE Email Value_Object SHALL reject any email that does not match RFC 5322 format, exceeds 320 characters, or belongs to a disposable email domain list, throwing `DomainException(INVALID_EMAIL)`.
5. THE PhoneNumber Value_Object SHALL reject any phone number that does not conform to E.164 format (8–15 digits after the `+` prefix), throwing `DomainException(INVALID_PHONE_NUMBER)`.
6. THE RawPassword Value_Object SHALL reject any password shorter than 10 characters, longer than 128 characters, missing an uppercase letter, missing a lowercase letter, missing a digit, missing a special character, or present in the top-10,000 common passwords list, throwing `DomainException(WEAK_PASSWORD)`.
7. WHEN a signup request is received, THE UICP SHALL acquire a Distributed_Lock on the identity value before persisting to prevent race conditions between concurrent signup requests for the same identity.
8. WHEN a signup request carries an `X-Idempotency-Key` header, THE UICP SHALL cache the response for 24 hours and return the cached response for subsequent requests with the same key.
9. THE UICP SHALL hash passwords using bcrypt with the current adaptive Bcrypt_Rounds and a secret pepper before persisting the Credential.

---

### Requirement 3: Email and Phone Credential Authentication — Login

**User Story:** As a registered user, I want to log in with my email or phone and password so that I can obtain tokens and access protected resources.

#### Acceptance Criteria

1. WHEN a user submits valid credentials to `POST /auth/login`, THE UICP SHALL verify the password against the stored Credential, create a Session, mint an Access_Token and Refresh_Token, and return them with HTTP 200.
2. WHEN a login attempt is received, THE UICP SHALL compute a Threat_Score via the UEBA_Engine before evaluating the auth policy.
3. WHEN the UEBA_Engine returns a Threat_Score above 0.35 and the tenant MFA policy is `adaptive`, THE UICP SHALL return HTTP 202 with `mfaRequired: true` and a challenge token instead of issuing tokens.
4. WHEN the tenant MFA policy is `required`, THE UICP SHALL always return HTTP 202 with `mfaRequired: true` regardless of Threat_Score.
5. IF a user account has status DELETED, THEN THE UICP SHALL return HTTP 401 with error code `ACCOUNT_DELETED`.
6. IF a user account has status SUSPENDED and `suspendUntil` is in the future, THEN THE UICP SHALL return HTTP 401 with error code `ACCOUNT_SUSPENDED` and a `retryAfter` timestamp.
7. IF a user account has status PENDING, THEN THE UICP SHALL return HTTP 401 with error code `ACCOUNT_NOT_ACTIVATED`.
8. THE UICP SHALL use timing-safe comparison when checking whether an identity exists to prevent user enumeration via timing attacks.
9. WHEN a login succeeds and the Credential requires rehashing (bcrypt rounds changed), THE UICP SHALL rehash the password asynchronously without blocking the response.
10. THE UICP SHALL enforce a rate limit of 20 requests per minute per IP on `POST /auth/login`.

---

### Requirement 4: Password Management

**User Story:** As an authenticated user, I want to change my password and reset it if forgotten so that I can maintain account security.

#### Acceptance Criteria

1. WHEN an authenticated user submits a valid current password and new password to `POST /auth/password/change`, THE UICP SHALL verify the current password, update the Credential with the new hash, and invalidate all existing sessions except the current one.
2. WHEN a user submits `POST /auth/password/reset/request` with an email or phone, THE UICP SHALL dispatch a password reset OTP and return HTTP 200 with the same response body regardless of whether the identity exists (timing-safe).
3. WHEN a user submits a valid reset token and new password to `POST /auth/password/reset/confirm`, THE UICP SHALL consume the reset token atomically, update the Credential, revoke all active sessions, and revoke all Refresh_Token families.
4. THE UICP SHALL enforce a rate limit of 3 requests per minute per IP on `POST /auth/password/reset/request`.
5. WHEN a password is changed, THE UICP SHALL emit a `PasswordChangedEvent` to the Outbox_Event store within the same database transaction.

---

### Requirement 5: OAuth 2.0 Social Login

**User Story:** As a user, I want to log in with my Google, GitHub, Apple, or Microsoft account so that I can authenticate without managing a separate password.

#### Acceptance Criteria

1. WHEN a user initiates OAuth login via `GET /auth/oauth/{provider}`, THE UICP SHALL generate a CSRF state parameter, store it in Redis with a short TTL, and redirect the user to the provider's authorization endpoint.
2. WHEN the OAuth provider redirects to `GET /auth/oauth/{provider}/callback`, THE UICP SHALL verify the `state` parameter against the stored value before proceeding.
3. WHEN the OAuth callback contains a valid authorization code, THE UICP SHALL exchange it for provider tokens, extract the user's `sub`, email, and profile data, and upsert the Identity.
4. IF an OAuth identity with the same `providerSub` already exists for the tenant, THEN THE UICP SHALL link the login to the existing User_Aggregate and update the encrypted provider data.
5. IF no matching OAuth identity exists, THEN THE UICP SHALL create a new User_Aggregate, link the OAuth Identity as pre-verified, and activate the user.
6. WHEN OAuth login succeeds, THE UICP SHALL create a Session, mint an Access_Token and Refresh_Token, and redirect the client with the tokens.
7. THE UICP SHALL support the following OAuth providers: Google, GitHub, Apple, and Microsoft.

---

### Requirement 6: MFA via OTP

**User Story:** As a user, I want to verify my identity with a one-time password so that my account is protected by a second factor.

#### Acceptance Criteria

1. WHEN an OTP is requested via `POST /auth/otp/send`, THE UICP SHALL generate a cryptographically random 6-digit code, store it in Redis with a 300-second TTL, and deliver it via the user's verified email or phone channel.
2. WHEN a user submits a valid OTP code to `POST /auth/otp/verify`, THE UICP SHALL consume the code atomically using Redis `GETDEL` (single-use guarantee) and return HTTP 200.
3. IF the submitted OTP code does not match the stored code, THEN THE UICP SHALL return HTTP 400 with error code `INVALID_OTP`.
4. IF the OTP code has already been consumed, THEN THE UICP SHALL return HTTP 400 with error code `ALREADY_USED`.
5. IF the OTP code has expired (TTL elapsed), THEN THE UICP SHALL return HTTP 400 with error code `OTP_EXPIRED`.
6. WHEN OTP verification succeeds for the `IDENTITY_VERIFICATION` purpose, THE UICP SHALL call `user.verifyIdentity(identityId)` on the User_Aggregate, which SHALL trigger `user.activate()` if this is the first verified identity.
7. WHEN OTP verification succeeds for the `MFA` purpose, THE UICP SHALL set the Session status to ACTIVE and mark `mfaVerified = true`.
8. THE UICP SHALL use timing-safe comparison when validating OTP codes to prevent timing attacks.
9. THE UICP SHALL enforce a rate limit of 10 requests per minute per user on `POST /auth/otp/verify`.

---

### Requirement 7: JWT Token Lifecycle

**User Story:** As a client application, I want to obtain, refresh, and validate JWT tokens so that I can authenticate API requests without repeated credential checks.

#### Acceptance Criteria

1. WHEN a login or OAuth flow succeeds, THE Token_Service SHALL mint an Access_Token as an RS256-signed JWT with a 15-minute TTL, embedding the user's `roles` and `perms` claims so that downstream services can authorize without a database call.
2. WHEN a login or OAuth flow succeeds, THE Token_Service SHALL mint a Refresh_Token as an RS256-signed JWT with a 7-day TTL, carrying a `fid` (family ID) claim.
3. WHEN a client submits a valid Refresh_Token to `POST /auth/refresh`, THE UICP SHALL acquire a pessimistic write lock on the token family, revoke the submitted token, mint a new Access_Token and Refresh_Token in the same family, and return them.
4. IF a Refresh_Token that has already been rotated is submitted to `POST /auth/refresh`, THEN THE UICP SHALL revoke all tokens in the same family, invalidate all user sessions, and return HTTP 401 with error code `REFRESH_TOKEN_REUSE`.
5. WHEN a token is added to the blocklist, THE UICP SHALL store the `jti` in a Redis sorted set with the token's expiry as the score, enabling O(1) blocklist checks.
6. THE UICP SHALL expose a `GET /.well-known/jwks.json` endpoint returning all active and deprecated RSA public keys in JWK format with `Cache-Control: public, max-age=3600`.
7. WHEN validating an Access_Token, THE UICP SHALL verify the RS256 signature, check the `exp` claim, verify the `iss` and `aud` claims, and check the `jti` against the Redis blocklist.
8. THE UICP SHALL support JWT signing key rotation with a 7-day overlap window during which both the old and new keys are served via the JWKS endpoint.
9. WHEN a JWT signing key is rotated, THE UICP SHALL generate a new RSA-4096 key pair, assign a new `kid`, and begin signing new tokens with the new key while continuing to verify tokens signed with the old key.
10. THE UICP SHALL expose a gRPC `ValidateToken` RPC for internal service-to-service token validation without HTTP overhead.

---

### Requirement 8: Session Management

**User Story:** As a user, I want my sessions to be managed securely so that I can view, control, and revoke my active sessions across devices.

#### Acceptance Criteria

1. WHEN a session is created, THE Session_Service SHALL store the session data as a Redis Hash with a TTL equal to the tenant's `session_ttl_s` configuration (default 86400 seconds).
2. WHEN a session is created, THE Session_Service SHALL add the session ID to a Redis Sorted Set keyed by `user-sessions:{tenantId}:{userId}` with the creation timestamp as the score.
3. WHEN the number of active sessions for a user reaches the tenant's `max_sessions_per_user` limit, THE Session_Service SHALL evict the oldest session (lowest score in the Sorted Set) before creating the new session.
4. WHEN an authenticated request is processed, THE Session_Service SHALL extend the session TTL to the full `session_ttl_s` value (sliding TTL).
5. WHEN a user calls `POST /auth/logout`, THE UICP SHALL invalidate the current session in Redis and add the Access_Token `jti` to the blocklist with the remaining TTL.
6. WHEN a user calls `POST /auth/logout-all`, THE UICP SHALL invalidate all sessions for the user, add all active Access_Token JTIs to the blocklist, and revoke all Refresh_Token families.
7. WHEN a user calls `GET /users/me/sessions`, THE UICP SHALL return all active sessions with device type, browser, OS, IP hash, creation time, and MFA verification status.
8. WHEN a user calls `DELETE /users/me/sessions/{id}`, THE UICP SHALL invalidate the specified session and add its Access_Token `jti` to the blocklist.
9. THE Session_Service SHALL parse the User-Agent string to extract browser name, OS, and device type (desktop, mobile, tablet) for each session.
10. WHEN a device fingerprint is present and MFA has been verified in a session, THE Session_Service SHALL add the device fingerprint to the user's trusted devices set in Redis.

---

### Requirement 9: ABAC Policy Engine

**User Story:** As a tenant administrator, I want to define attribute-based access control policies so that I can enforce fine-grained authorization rules based on subject, resource, and environment attributes.

#### Acceptance Criteria

1. THE ABAC_Policy SHALL support a DSL with the following operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `IN`, `NOT IN`, `CONTAINS`, and logical connectors `AND`, `OR`, `NOT`.
2. THE ABAC_Policy DSL SHALL support attribute references in the form `subject.ATTR`, `resource.ATTR`, and `env.ATTR`.
3. WHEN an ABAC_Policy with effect `DENY` matches a request context, THE UICP SHALL return DENY regardless of any matching ALLOW policies (deny override).
4. WHEN no DENY policy matches and at least one ALLOW policy matches, THE UICP SHALL return ALLOW.
5. WHEN no policy matches, THE UICP SHALL return DENY (implicit deny default).
6. THE ABAC_Policy_Engine SHALL evaluate policies in descending priority order.
7. THE ABAC_Policy_Engine SHALL JIT-compile DSL conditions to native JavaScript functions and cache compiled functions in an LRU cache of 500 entries.
8. THE ABAC_Policy_Engine SHALL cache all active policies for a tenant in an LRU cache of 100 tenants with a 60-second TTL.
9. WHEN an ABAC_Policy is created, updated, or deleted, THE UICP SHALL immediately invalidate the tenant's policy cache.
10. THE UICP SHALL expose `POST /iam/policies/evaluate` for dry-run policy evaluation and `GET /iam/policies/simulate` for simulating all policies against a given context.
11. WHEN an ABAC_Policy DSL condition is submitted, THE UICP SHALL validate it against the grammar before persisting and return HTTP 400 with a descriptive error if invalid.

---

### Requirement 10: RBAC — Roles and Permissions

**User Story:** As a tenant administrator, I want to manage roles and permissions so that I can assign coarse-grained access rights to users.

#### Acceptance Criteria

1. THE UICP SHALL support creating, reading, updating, and deleting roles scoped to a tenant via `POST /iam/roles`, `GET /iam/roles`, `PUT /iam/roles/{id}`, and `DELETE /iam/roles/{id}`.
2. THE UICP SHALL support creating and deleting permissions in `resource:action` format via `POST /iam/permissions` and `DELETE /iam/permissions/{id}`.
3. WHEN permissions are assigned to a role via `POST /iam/roles/{id}/permissions`, THE UICP SHALL associate the permissions with the role and emit a `RolePermissionsUpdatedEvent` to the outbox.
4. WHEN a role is assigned to a user via `POST /iam/users/{userId}/roles`, THE UICP SHALL persist the assignment and emit a `RoleAssignedEvent` to the outbox.
5. WHEN a role is revoked from a user via `DELETE /iam/users/{userId}/roles/{roleId}`, THE UICP SHALL remove the assignment and emit a `RoleRevokedEvent` to the outbox.
6. WHEN an Access_Token is minted, THE Token_Service SHALL embed all role names and all effective permissions (expanded from all assigned roles) in the `roles` and `perms` JWT claims.
7. THE UICP SHALL prevent deletion of a role that is currently assigned to one or more users, returning HTTP 409.
8. THE UICP SHALL prevent deletion of a permission that is currently assigned to one or more roles, returning HTTP 409.
9. WHEN a role assignment changes, THE UICP SHALL invalidate the user's active Access_Tokens by adding their JTIs to the blocklist so that the next token refresh picks up the new permissions.


---

### Requirement 11: UEBA Threat Scoring

**User Story:** As a security engineer, I want the system to automatically score the risk of every authentication event so that suspicious logins are detected and challenged before they succeed.

#### Acceptance Criteria

1. WHEN a login attempt is received, THE UEBA_Engine SHALL compute a composite Threat_Score in the range [0.0, 1.0] from five signals: velocity, geo, device, credential stuffing, and Tor exit node.
2. THE VelocityAnalyzer SHALL compute a score using four sliding windows: user 1-minute (threshold 5), user 5-minute (threshold 15), IP 1-minute (threshold 10), and IP 10-minute (threshold 30), weighted equally at 0.25 each.
3. THE GeoAnalyzer SHALL compute a score of 1.0 when the login speed between the last known location and the current location exceeds 900 km/h (impossible travel), 0.6 when the country changes, 0.2 when only the city changes, and 0.0 otherwise.
4. THE GeoAnalyzer SHALL use the local MaxMind GeoLite2 database for IP geolocation to avoid external API dependencies.
5. THE DeviceAnalyzer SHALL compute a score of 0.0 for known trusted devices, 0.5 for unknown devices when the user has at least one known device, and 0.1 for unknown devices when the user has no known devices.
6. THE CredentialStuffingAnalyzer SHALL compute a score based on failed login counts across sliding 10-minute windows, reaching 1.0 when global failures from an IP exceed 30.
7. THE TorExitNodeChecker SHALL assign a score of 0.4 when the login IP is in the Tor exit node list (updated every 6 hours from the Tor Project bulk exit list).
8. THE UEBA_Engine SHALL compute the composite Threat_Score as a weighted sum: `0.35 * velocity + 0.25 * geo + 0.20 * device + 0.15 * credentialStuffing + 0.05 * tor`.
9. WHEN the composite Threat_Score exceeds 0.75, THE UICP SHALL create a SOC_Alert with the appropriate Kill_Chain_Stage and signal breakdown.
10. WHEN a Threat_Score exceeds 0.90, THE UICP SHALL automatically lock the user account in Redis for a configurable TTL.

---

### Requirement 12: SOC Alerting and Workflow

**User Story:** As a SOC analyst, I want to view, acknowledge, resolve, and mark false-positive security alerts so that I can manage the threat response workflow.

#### Acceptance Criteria

1. WHEN a SOC_Alert is created, THE UICP SHALL persist it as an immutable INSERT-only record with a HMAC checksum, initial workflow state `OPEN`, and the full signal breakdown in JSON.
2. WHEN a SOC analyst calls `PATCH /soc/alerts/{id}/acknowledge`, THE UICP SHALL transition the alert workflow from `OPEN` to `ACKNOWLEDGED` and record the analyst's user ID and timestamp.
3. WHEN a SOC analyst calls `PATCH /soc/alerts/{id}/resolve`, THE UICP SHALL transition the alert workflow from `ACKNOWLEDGED` to `RESOLVED` and record the analyst's user ID and timestamp.
4. WHEN a SOC analyst calls `PATCH /soc/alerts/{id}/false-positive`, THE UICP SHALL transition the alert workflow to `FALSE_POSITIVE` from any state and notify the adaptive tuner to adjust thresholds.
5. THE UICP SHALL expose `GET /soc/alerts` with filtering by workflow state, threat score range, kill chain stage, and date range.
6. THE UICP SHALL expose a WebSocket endpoint at `/soc/feed` that streams real-time `soc:alert:created`, `soc:alert:updated`, and `soc:metrics` events to connected SOC analysts.
7. WHEN a SOC analyst connects to the WebSocket feed, THE UICP SHALL automatically join the analyst to the tenant's SOC room.
8. THE UICP SHALL expose `POST /soc/users/{userId}/lock` for SOC analysts to manually lock a user account with a custom TTL.
9. THE UICP SHALL expose `POST /soc/users/{userId}/revoke-sessions` for SOC analysts to force-revoke all sessions for a user.
10. WHEN a SOC_Alert HMAC checksum fails verification on read, THE UICP SHALL throw an integrity violation exception and emit a critical metric.

---

### Requirement 13: Field-Level Encryption

**User Story:** As a security architect, I want all sensitive fields to be encrypted at rest with tenant-isolated keys so that a database breach does not expose plaintext PII.

#### Acceptance Criteria

1. THE Encryption_Service SHALL encrypt sensitive fields (identity values, display names, metadata, audit metadata, tenant settings, OAuth provider data, JWT private keys) using AES-256-GCM with a 12-byte random IV per encryption operation.
2. THE Encryption_Service SHALL derive per-context, per-tenant encryption keys using HKDF with SHA-256, where the `info` parameter includes both the Encryption_Context name and the TenantId.
3. THE Encryption_Service SHALL store encrypted values in the format `base64(iv).base64(tag).base64(ciphertext).kid` to enable key rotation without re-reading all rows.
4. WHEN decrypting a field, THE Encryption_Service SHALL use the `kid` stored with the ciphertext to select the correct master key, supporting decryption of values encrypted with deprecated keys.
5. THE Encryption_Service SHALL support envelope encryption for fields exceeding 4KB, generating a per-field Data Encryption Key (DEK) encrypted with the context Key Encryption Key (KEK).
6. WHEN the application starts, THE UICP SHALL perform an encryption roundtrip test for every Encryption_Context and refuse to start if any test fails.
7. WHEN the application starts, THE UICP SHALL verify that decrypting a value with a different Encryption_Context fails (cross-context isolation check).
8. THE Encryption_Service SHALL compute HMAC-SHA256 of identity values (email, phone) for use as searchable lookup keys, enabling O(1) identity lookups without decryption.
9. WHEN an encryption key is rotated, THE UICP SHALL support a background re-encryption job that re-encrypts all rows with the old `kid` to the new `kid` in batches of 1000.

---

### Requirement 14: Distributed Locking

**User Story:** As a system architect, I want distributed locks to prevent race conditions in concurrent operations so that data integrity is maintained across multiple pod replicas.

#### Acceptance Criteria

1. THE Distributed_Lock SHALL be acquired using Redis `SET key value NX PX ttl` to ensure atomicity (no TOCTOU race condition).
2. THE Distributed_Lock SHALL be released using a Lua script that atomically checks the lock value matches the owner's token before deleting, preventing a pod from releasing another pod's lock.
3. WHEN a lock cannot be acquired after the configured `maxRetries` (default 3) with exponential backoff and jitter, THE UICP SHALL throw `ConflictException`.
4. THE Distributed_Lock SHALL support TTL extension via an atomic Lua script that checks ownership before extending.
5. THE UICP SHALL use Distributed_Locks for: signup identity creation, session creation per user, and refresh token family rotation.
6. AT MOST one process SHALL hold a given lock key at any point in time.

---

### Requirement 15: Circuit Breakers and Resilience

**User Story:** As a platform operator, I want circuit breakers on all external dependencies so that a failure in one component does not cascade to bring down the entire system.

#### Acceptance Criteria

1. THE UICP SHALL implement Circuit_Breakers for MySQL, Redis, OTP delivery (Firebase/SMTP), and GeoIP lookups.
2. WHEN a Circuit_Breaker trips open, THE UICP SHALL activate the configured fallback: session reads fall back to MySQL, rate limiting falls back to in-memory token buckets, and distributed locks fall back to MySQL advisory locks.
3. WHEN a Circuit_Breaker is open, THE UICP SHALL emit the metric `uicp_circuit_breaker_state{name}=1` and fire the `UicpCircuitBreakerOpen` Prometheus alert.
4. WHEN a Circuit_Breaker enters HALF_OPEN state after the reset timeout, THE UICP SHALL allow a single probe request and transition to CLOSED on success or back to OPEN on failure.
5. THE UICP SHALL implement timeout hierarchies: DB query 2000ms, Redis command 500ms, external OAuth call 5000ms, GeoIP lookup 100ms, OTP send 3000ms.
6. WHEN a DB deadlock is detected (`ER_LOCK_DEADLOCK`), THE UICP SHALL retry the operation up to 3 times with exponential backoff and jitter before throwing `InfrastructureException(DB_UNAVAILABLE)`.

---

### Requirement 16: Adaptive Systems

**User Story:** As a platform operator, I want the system to automatically tune its performance parameters based on current load so that it maintains optimal throughput and security under varying conditions.

#### Acceptance Criteria

1. THE UICP SHALL calibrate Bcrypt_Rounds at startup and every 30 minutes by measuring the p95 hash time over 5 samples, targeting 200ms, and adjusting rounds within the range [10, 13].
2. WHEN the server load score exceeds 0.80, THE UICP SHALL use the minimum Bcrypt_Rounds (10) regardless of calibration results.
3. THE UICP SHALL compute a composite server load score every 5 seconds using Exponential Moving Average (alpha=0.15) of CPU (30% weight), memory (30% weight), and event loop lag (40% weight).
4. THE UICP SHALL adjust cache TTLs adaptively based on per-key-type hit rates: multiplier 1.5 for hit rate >= 90%, 1.2 for >= 70%, 1.0 for >= 50%, and 0.7 below 50%, with ±10% jitter to prevent thundering herd.
5. THE UICP SHALL expand the DB connection pool by 2 connections when more than 5 requests are waiting, and shrink by 1 when idle connections exceed twice the minimum, within the bounds [5, 20].
6. THE UICP SHALL adjust BullMQ worker concurrency based on load score and queue depth: reducing by 50% under load > 0.80, increasing by 50% when queue depth > 500.
7. THE UICP SHALL adjust the rate limit multiplier every 30 seconds: reducing to 70% of current when error rate exceeds 10%, restoring by 5% per cycle when error rate is below 1%.
8. WHEN any adaptive parameter changes, THE UICP SHALL log the change at INFO level with the old value, new value, reason, and current load score.

---

### Requirement 17: Transactional Outbox Pattern

**User Story:** As a system architect, I want domain events to be published reliably without distributed transactions so that side effects (audit logs, SOC alerts, emails) are guaranteed to execute even if the application crashes.

#### Acceptance Criteria

1. WHEN a command handler writes domain data to the database, THE UICP SHALL insert the corresponding Outbox_Event into the `outbox_events` table within the same database transaction.
2. THE Outbox_Relay_Worker SHALL poll the `outbox_events` table every 500ms using `SELECT ... FOR UPDATE SKIP LOCKED LIMIT 50` to claim a batch of pending events without conflicts between concurrent pods.
3. WHEN an Outbox_Event is claimed, THE Outbox_Relay_Worker SHALL enqueue it to the appropriate BullMQ queue and mark it as `PUBLISHED`.
4. WHEN an Outbox_Event fails processing, THE UICP SHALL increment the attempt counter and retry with exponential backoff up to 5 attempts.
5. WHEN an Outbox_Event reaches 5 failed attempts, THE UICP SHALL move it to `DLQ` status, emit the metric `uicp_outbox_dlq_total`, and create a SOC_Alert.
6. EVERY Outbox_Event inserted into the `outbox_events` table SHALL eventually reach status `PUBLISHED` or `DLQ` — no event SHALL remain in `PENDING` status indefinitely.

---

### Requirement 18: Event Sourcing

**User Story:** As a system architect, I want all User_Aggregate state changes to be recorded as an ordered sequence of domain events so that the aggregate can be reconstituted from its event history.

#### Acceptance Criteria

1. THE UICP SHALL persist every User_Aggregate state change as a Domain_Event in the `domain_events` table with a monotonically increasing `aggregate_seq` per aggregate.
2. WHEN loading a User_Aggregate, THE UICP SHALL replay all Domain_Events for the aggregate in ascending `aggregate_seq` order to reconstitute the current state.
3. THE Event_Store SHALL enforce optimistic concurrency using a `UNIQUE KEY (aggregate_id, aggregate_seq)` constraint, throwing `ConflictException(VERSION_CONFLICT)` on duplicate sequence numbers.
4. THE UICP SHALL support the following domain events: `UserCreated`, `UserActivated`, `UserSuspended`, `UserUnsuspended`, `UserDeleted`, `IdentityLinked`, `IdentityVerified`, `SessionCreated`, `SessionRevoked`, `LoginSucceeded`, `LoginFailed`, `TokenRefreshed`, `TokenReuseDetected`, `OtpVerified`, `PasswordChanged`, `ThreatDetected`.
5. WHEN concurrent updates attempt to append events with the same `aggregate_seq`, THE UICP SHALL ensure exactly one succeeds and the rest receive `ConflictException(VERSION_CONFLICT)`.
6. Domain_Event payloads SHALL be encrypted using AES-256-GCM with the `AUDIT_METADATA` Encryption_Context before storage.

---

### Requirement 19: Idempotency

**User Story:** As a client developer, I want to safely retry failed requests without causing duplicate operations so that network failures do not result in duplicate accounts, charges, or state changes.

#### Acceptance Criteria

1. WHEN a request carries an `X-Idempotency-Key` header, THE IdempotencyInterceptor SHALL check Redis for a cached response before processing the request.
2. IF a cached response exists for the idempotency key, THE UICP SHALL return the cached response with HTTP status 200 and the header `X-Idempotency-Replayed: true` without re-executing the handler.
3. WHEN a request with an idempotency key is processed successfully, THE UICP SHALL cache the response in Redis with a 24-hour TTL.
4. THE UICP SHALL require idempotency keys on the following endpoints: `POST /auth/signup`, `DELETE /users/me`, `POST /users/me/identities`, `DELETE /users/me/identities/{id}`, `POST /admin/users`, `POST /admin/users/{id}/suspend`, `POST /admin/users/{id}/unsuspend`, `DELETE /admin/users/{id}`, `DELETE /admin/users/{id}/sessions`, `POST /soc/users/{userId}/lock`, `POST /soc/users/{userId}/revoke-sessions`, `POST /platform/tenants`, `POST /platform/keys/rotate-encryption`, `POST /platform/keys/rotate-jwt`, `POST /platform/schema/migrate`.
5. FOR ALL requests with the same idempotency key, THE UICP SHALL return the same response body regardless of how many times the request is retried.

---

### Requirement 20: Rate Limiting

**User Story:** As a platform operator, I want multi-layer rate limiting so that the system is protected from abuse, brute force attacks, and denial-of-service attempts.

#### Acceptance Criteria

1. THE Rate_Limiter SHALL implement a token bucket algorithm with per-IP and per-user limits enforced via Redis atomic INCR operations.
2. THE UICP SHALL enforce the following rate limits: `POST /auth/signup` 10/min/IP, `POST /auth/login` 20/min/IP, `POST /auth/refresh` 60/min/user, `POST /auth/otp/send` 5/min/user, `POST /auth/otp/verify` 10/min/user, `POST /auth/password/change` 5/min/user, `POST /auth/password/reset/request` 3/min/IP.
3. WHEN a rate limit is exceeded, THE UICP SHALL return HTTP 429 with a `Retry-After` header indicating when the limit resets.
4. THE Rate_Limiter SHALL apply the adaptive rate limit multiplier (from Requirement 16) to all per-tenant limits.
5. WHEN the BullMQ queue depth exceeds the HIGH_WATERMARK (1000), THE UICP SHALL set a backpressure flag in Redis and tighten rate limits by a factor of 0.7 for non-critical endpoints.
6. THE token bucket remaining count SHALL always be in the range [0, capacity] — it SHALL never go negative or exceed the configured capacity.


---

### Requirement 21: Audit Logging

**User Story:** As a compliance officer, I want an immutable, tamper-evident audit log of all security-relevant actions so that I can demonstrate compliance and investigate incidents.

#### Acceptance Criteria

1. THE UICP SHALL write an audit log entry for every authentication event (login success, login failure, logout, password change, OTP verification), every user mutation (create, suspend, delete), every IAM change (role assignment, policy change), and every SOC action (alert acknowledge, resolve, false-positive).
2. WHEN an audit log entry is written, THE UICP SHALL compute an HMAC-SHA256 checksum over the entry's fields and store it in the `checksum` column.
3. WHEN an audit log entry is read, THE UICP SHALL verify the HMAC checksum and throw an integrity violation exception if the checksum does not match.
4. THE `audit_logs` table SHALL be INSERT-only at the application level — no UPDATE or DELETE operations SHALL be issued by the application.
5. THE UICP SHALL revoke UPDATE and DELETE grants on the `audit_logs` table for the application database user.
6. THE UICP SHALL encrypt audit log metadata using AES-256-GCM with the `AUDIT_METADATA` Encryption_Context.
7. THE UICP SHALL expose `GET /admin/audit-logs` with cursor-based pagination, filtering by actor, action, resource type, and date range.
8. THE UICP SHALL expose `GET /admin/audit-logs/export` for asynchronous CSV/JSON export of audit logs.
9. THE `audit_logs` table SHALL be partitioned by `RANGE(created_at)` with quarterly partitions to support archival via `DROP PARTITION`.

---

### Requirement 22: Health Endpoints and Observability

**User Story:** As a platform operator, I want health endpoints and comprehensive observability so that I can monitor system health, diagnose issues, and meet SLA targets.

#### Acceptance Criteria

1. THE UICP SHALL expose `GET /health/live` returning HTTP 200 when the process is alive, used by Kubernetes liveness probes.
2. THE UICP SHALL expose `GET /health/ready` returning HTTP 200 when the service is ready to serve traffic (DB and Redis reachable), and HTTP 503 otherwise, used by Kubernetes readiness probes.
3. THE UICP SHALL expose `GET /health/deep` returning a detailed health check including DB primary latency, DB replica latency and replication lag, Redis latency, BullMQ queue depths, encryption roundtrip time, and GeoIP DB status.
4. THE UICP SHALL expose `GET /metrics` in Prometheus text format with all counters, gauges, and histograms defined in the metric catalog.
5. THE UICP SHALL emit the following counters: `uicp_auth_attempts_total`, `uicp_signup_total`, `uicp_otp_sent_total`, `uicp_otp_verified_total`, `uicp_token_minted_total`, `uicp_token_refreshed_total`, `uicp_errors_total`, `uicp_soc_alerts_total`, `uicp_circuit_breaker_fire_total`, `uicp_outbox_published_total`, `uicp_outbox_dlq_total`, `uicp_adaptive_parameter_change_total`.
6. THE UICP SHALL emit the following histograms: `uicp_request_duration_ms`, `uicp_db_query_duration_ms`, `uicp_redis_command_duration_ms`, `uicp_bcrypt_hash_duration_ms`, `uicp_ueba_score_duration_ms`, `uicp_token_validation_duration_ms`.
7. THE UICP SHALL instrument all operations with OpenTelemetry spans, propagating W3C TraceContext headers, and export traces to the configured OTLP endpoint.
8. THE UICP SHALL use Pino structured logging in NDJSON format, auto-injecting `requestId`, `traceId`, `tenantId`, `userId`, and `sessionId` from the CLS context into every log line.
9. THE UICP SHALL redact PII fields (`email`, `password`, `phone`, `ip`) from all log output using Pino redact.
10. THE UICP SHALL propagate the CLS context (requestId, tenantId, userId, traceId, sessionId) through the entire async call stack via AsyncLocalStorage so that all log lines and spans within a request share the same correlation IDs.

---

### Requirement 23: Graceful Shutdown

**User Story:** As a platform operator, I want the service to shut down gracefully so that in-flight requests are completed and no data is lost during pod restarts or deployments.

#### Acceptance Criteria

1. WHEN the UICP receives a SIGTERM signal, THE UICP SHALL stop accepting new connections and allow in-flight requests up to 25 seconds to complete before forcefully terminating.
2. WHEN graceful shutdown begins, THE UICP SHALL stop the BullMQ workers from picking up new jobs while allowing currently processing jobs to complete.
3. WHEN graceful shutdown begins, THE UICP SHALL close the DB connection pool and Redis connections cleanly after all in-flight operations complete.
4. THE Kubernetes Deployment SHALL set `terminationGracePeriodSeconds: 35` (greater than the 25-second drain window) to allow the graceful shutdown to complete.
5. THE Kubernetes Deployment SHALL include a `preStop` lifecycle hook with a 5-second sleep to allow the load balancer to drain connections before SIGTERM is sent.

---

### Requirement 24: API Surface — Authentication API

**User Story:** As a client developer, I want a well-defined authentication API so that I can integrate signup, login, token management, MFA, OAuth, and password management into my application.

#### Acceptance Criteria

1. THE UICP SHALL expose the following Authentication API endpoints: `POST /auth/signup`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `POST /auth/logout-all`, `POST /auth/otp/send`, `POST /auth/otp/verify`, `POST /auth/password/change`, `POST /auth/password/reset/request`, `POST /auth/password/reset/confirm`, `GET /auth/oauth/{provider}`, `GET /auth/oauth/{provider}/callback`, `GET /.well-known/jwks.json`, `GET /.well-known/openid-configuration`.
2. ALL API responses SHALL be wrapped in a standard envelope: `{ data: T, meta: { requestId: string, timestamp: string } }`.
3. ALL API error responses SHALL follow the format: `{ error: { code: string, message: string, field?: string, retryAfter?: number, remaining?: number }, meta: { requestId: string, timestamp: string } }`.
4. THE UICP SHALL validate all request bodies using Zod schemas before invoking command handlers, returning HTTP 400 with field-level error details on validation failure.
5. ALL requests SHALL require the `X-Tenant-ID` header; THE TenantGuard SHALL return HTTP 400 if the header is missing or invalid.
6. THE UICP SHALL apply Helmet security headers to all HTTP responses.

---

### Requirement 25: API Surface — User Self-Service, IAM, Admin, SOC, and Platform APIs

**User Story:** As a tenant administrator, SOC analyst, and platform operator, I want dedicated API groups for user management, IAM, administration, security operations, and platform management so that each actor has a purpose-built interface.

#### Acceptance Criteria

1. THE UICP SHALL expose the User Self-Service API at `/users/me` with endpoints for profile management, session management, device management, identity management, audit log access, and permissions query.
2. THE UICP SHALL expose the IAM Management API at `/iam` with endpoints for role CRUD, permission CRUD, user-role assignment, ABAC policy CRUD, and policy evaluation tools.
3. THE UICP SHALL expose the Tenant Administration API at `/admin` with endpoints for user management (list, create, update, suspend, unsuspend, delete), audit log access, tenant configuration, and OAuth client app management.
4. THE UICP SHALL expose the Security Operations API at `/soc` with endpoints for alert management, user threat history, session management, account locking, metrics, threshold configuration, and IP history.
5. THE UICP SHALL expose the Platform API at `/platform` with endpoints for tenant provisioning, encryption key rotation, JWT key rotation, health monitoring, and schema migration.
6. THE UICP SHALL expose a gRPC service on port 5000 with `ValidateToken`, `CheckPermission`, and `GetUserClaims` RPCs for internal service-to-service communication.
7. THE UICP SHALL expose a WebSocket namespace at `/soc` for real-time SOC dashboard event streaming.
8. ALL API mutations SHALL be audit-logged with the actor ID, action, resource type, resource ID, and metadata.

---

### Requirement 26: DB-Agnostic Adapter Pattern

**User Story:** As a platform operator, I want the system to support both MySQL and PostgreSQL so that I can choose the database that fits my infrastructure without changing application code.

#### Acceptance Criteria

1. THE UICP SHALL implement all repository interfaces (IUserRepository, IIdentityRepository, ISessionStore, ITokenRepository, IEventStore, IOutboxRepository, IAbacPolicyRepository, IAlertRepository) as port interfaces with no framework imports in the domain layer.
2. THE UICP SHALL provide concrete implementations of all repository interfaces for both MySQL 8.0 and PostgreSQL.
3. WHEN the `DB_ADAPTER` environment variable is set to `postgres`, THE UICP SHALL use the PostgreSQL implementations; when set to `mysql` (default), THE UICP SHALL use the MySQL implementations.
4. THE UICP SHALL route all write operations (INSERT, UPDATE, DELETE, SELECT FOR UPDATE) to the primary database and all read operations to read replicas.
5. WHEN strong consistency is required (token rotation, OTP consume, version check), THE UICP SHALL route reads to the primary database.
6. THE UICP SHALL track all applied database migrations in the `schema_versions` table with SHA-256 checksums, and refuse to start if any applied migration's checksum does not match the stored value.

---

### Requirement 27: Kubernetes Deployment

**User Story:** As a platform operator, I want the service to be deployed on Kubernetes with autoscaling, disruption budgets, and health probes so that it meets the 99.99% availability target.

#### Acceptance Criteria

1. THE UICP Kubernetes Deployment SHALL configure liveness probes on `GET /health/live` with `initialDelaySeconds: 10` and `periodSeconds: 10`.
2. THE UICP Kubernetes Deployment SHALL configure readiness probes on `GET /health/ready` with `initialDelaySeconds: 5`, `periodSeconds: 5`, and `failureThreshold: 3`.
3. THE UICP SHALL deploy with a minimum of 2 replicas and a maximum of 20 replicas.
4. THE UICP HPA SHALL scale based on CPU utilization (target 70%) and the custom metric `uicp_request_queue_depth` (target average value 100).
5. THE UICP PodDisruptionBudget SHALL set `minAvailable: 1` to ensure at least one pod is always available during voluntary disruptions.
6. THE UICP pods SHALL be stateless — all application state SHALL reside in Redis or MySQL, not in pod memory.
7. THE UICP SHALL use a Redis Cluster with 3 primary shards and 1 replica each (6 nodes total) for session storage, rate limiting, and distributed locking.
8. THE UICP SHALL use a MySQL InnoDB Cluster with 1 primary and 2 read replicas.

---

### Requirement 28: User Aggregate State Machine

**User Story:** As a domain architect, I want the User_Aggregate to enforce valid state transitions so that users cannot be placed in invalid states.

#### Acceptance Criteria

1. THE User_Aggregate SHALL enforce the following state machine: PENDING → ACTIVE (via `activate()`), ACTIVE → SUSPENDED (via `suspend()`), SUSPENDED → ACTIVE (via `unsuspend()`), ACTIVE|SUSPENDED → DELETED (via `delete()`). DELETED is a terminal state.
2. WHEN `User.activate()` is called on a user without at least one verified Identity, THE UICP SHALL throw `DomainException(CANNOT_ACTIVATE_WITHOUT_VERIFIED_IDENTITY)`.
3. WHEN `User.activate()` is called on a user not in PENDING status, THE UICP SHALL throw `DomainException(INVALID_STATUS_TRANSITION)`.
4. WHEN `User.suspend()` is called on a user not in ACTIVE status, THE UICP SHALL throw `DomainException(INVALID_STATUS_TRANSITION)`.
5. WHEN `User.delete()` is called on a user already in DELETED status, THE UICP SHALL throw `DomainException(INVALID_STATUS_TRANSITION)`.
6. WHEN `User.linkIdentity()` is called and the user already has 3 identities of the same type, THE UICP SHALL throw `DomainException(MAX_IDENTITIES_PER_TYPE_EXCEEDED)`.
7. WHEN `User.linkIdentity()` is called with an identity whose value hash already exists for the same type, THE UICP SHALL throw `DomainException(IDENTITY_ALREADY_LINKED)`.
8. WHEN `User.verifyIdentity()` is called and the identity is already verified, THE UICP SHALL throw `DomainException(IDENTITY_ALREADY_VERIFIED)`.
9. WHEN `Session.revoke()` is called on a session already in REVOKED or EXPIRED status, THE UICP SHALL throw `DomainException(SESSION_ALREADY_TERMINATED)`.


---

## Non-Functional Requirements

### Requirement 29: Performance SLA Targets

**User Story:** As a platform operator, I want the system to meet defined latency and throughput targets so that users experience fast authentication and the system can handle enterprise-scale load.

#### Acceptance Criteria

1. THE UICP SHALL process token validation (JWT, no DB) with p50 <= 2ms, p95 <= 5ms, p99 <= 10ms at 10,000 RPS.
2. THE UICP SHALL process login (full flow) with p50 <= 80ms, p95 <= 200ms, p99 <= 400ms at 500 RPS.
3. THE UICP SHALL process signup with p50 <= 120ms, p95 <= 300ms, p99 <= 600ms at 200 RPS.
4. THE UICP SHALL process refresh token rotation with p50 <= 20ms, p95 <= 60ms, p99 <= 120ms at 2,000 RPS.
5. THE UICP SHALL process OTP verification with p50 <= 15ms, p95 <= 40ms, p99 <= 80ms at 1,000 RPS.
6. THE UICP SHALL process ABAC policy evaluation (cached) with p50 <= 1ms, p95 <= 3ms, p99 <= 8ms at 20,000 RPS.
7. THE UICP SHALL process session reads (Redis hit) with p50 <= 1ms, p95 <= 3ms, p99 <= 6ms at 15,000 RPS.
8. THE UICP SHALL process audit log writes (async outbox) with p50 <= 5ms, p95 <= 15ms, p99 <= 30ms at 5,000 RPS.

---

### Requirement 30: Availability and Scalability

**User Story:** As a platform operator, I want the system to achieve 99.99% availability and scale horizontally so that it can serve enterprise customers without downtime.

#### Acceptance Criteria

1. THE UICP SHALL achieve 99.99% availability (maximum 52 minutes downtime per year) through multi-replica deployment, Redis Sentinel/Cluster, MySQL read replicas, circuit breakers with fallback, and graceful shutdown.
2. THE UICP pods SHALL be stateless — no in-memory state that cannot be lost on restart — enabling horizontal scaling without coordination.
3. THE UICP SHALL scale from 2 to 20 pod replicas based on CPU utilization and queue depth metrics.
4. THE UICP SHALL use Redis hash tags (`{userId}`) to co-locate a user's sessions on a single Redis shard, enabling efficient session operations without cross-shard coordination.
5. THE UICP SHALL use `SELECT ... FOR UPDATE SKIP LOCKED` for outbox relay polling so that multiple pods can process the outbox concurrently without duplicate processing.
6. THE UICP SHALL route write operations to the MySQL primary and read operations to read replicas, monitoring replica lag and routing strong-consistency reads to the primary.

---

### Requirement 31: Security

**User Story:** As a security architect, I want the system to implement zero-trust security principles so that every request is authenticated, authorized, and audited.

#### Acceptance Criteria

1. THE UICP SHALL implement zero-trust: every request SHALL be authenticated via JWT, every action SHALL be authorized via ABAC/RBAC, and every mutation SHALL be audit-logged.
2. THE UICP SHALL never store plaintext PII — all sensitive fields SHALL be encrypted with AES-256-GCM before persistence.
3. THE UICP SHALL never log plaintext PII — all PII fields SHALL be redacted in log output.
4. THE UICP SHALL use RS256 (RSA-4096) for JWT signing so that downstream services can verify tokens using only the public JWKS endpoint without sharing a secret.
5. THE UICP SHALL pepper all password hashes with a secret pepper before bcrypt hashing, so that a database breach alone is insufficient to crack passwords.
6. THE UICP SHALL use timing-safe comparison for all security-sensitive equality checks (OTP codes, identity lookups, token comparisons) to prevent timing attacks.
7. THE UICP SHALL enforce CSRF protection on all OAuth flows via a state parameter stored in Redis.
8. THE UICP SHALL apply Helmet security headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, etc.) to all HTTP responses.
9. THE UICP SHALL enforce IP allowlists on the Platform API (`/platform`) endpoints.
10. THE UICP SHALL use parameterized SQL queries for all database operations to prevent SQL injection.

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Identity Uniqueness

For any tenant T, identity type, and identity value, there SHALL be at most one verified identity with that value and type within the tenant. Attempting to create a duplicate SHALL return `IDENTITY_ALREADY_EXISTS`.

**Validates: Requirements 2.3, 2.7**

---

### Property 2: Active User Has Verified Identity

For any User_Aggregate with status ACTIVE, there SHALL exist at least one verified Identity in the aggregate's identity list.

**Validates: Requirements 6.6, 28.2**

---

### Property 3: Token Family Integrity on Reuse

For any Refresh_Token that has been rotated, if the old token is submitted again (reuse attack), then ALL tokens in the same token family SHALL be revoked and ALL user sessions SHALL be invalidated.

**Validates: Requirements 7.4**

---

### Property 4: Optimistic Lock Consistency

For any two concurrent updates targeting the same User_Aggregate version, exactly one SHALL succeed and the other SHALL receive `ConflictException(VERSION_CONFLICT)`.

**Validates: Requirements 18.3, 18.5**

---

### Property 5: OTP Single-Use

For any OTP code that has been successfully verified, any subsequent verification attempt with the same code SHALL fail with `ALREADY_USED`.

**Validates: Requirements 6.2, 6.4**

---

### Property 6: Rate Limit Monotonicity

For any token bucket with a configured capacity, the remaining token count SHALL always be in the range [0, capacity] — it SHALL never go negative or exceed the capacity regardless of concurrent requests.

**Validates: Requirements 20.6**

---

### Property 7: Encryption Roundtrip

For any plaintext string and any Encryption_Context, decrypting the result of encrypting the plaintext with that context SHALL produce the original plaintext: `decrypt(encrypt(p, ctx), ctx) = p`.

**Validates: Requirements 13.1, 13.2, 13.6**

---

### Property 8: HMAC Determinism

For any input value and any Encryption_Context, computing the HMAC twice SHALL produce the same result: `hmac(v, ctx) = hmac(v, ctx)`.

**Validates: Requirements 13.8**

---

### Property 9: Session Expiry

For any Session with an `expiresAt` timestamp, after that timestamp has passed, looking up the session by ID SHALL return null.

**Validates: Requirements 8.1, 8.4**

---

### Property 10: Audit Immutability

For any audit log entry, issuing an UPDATE SQL statement targeting that entry's ID SHALL affect 0 rows.

**Validates: Requirements 21.4, 21.5**

---

### Property 11: ABAC Deny Override

For any policy set, subject, resource, and action, if any DENY policy matches the context, the decision SHALL be DENY regardless of any matching ALLOW policies or their priority values.

**Validates: Requirements 9.3, 9.5**

---

### Property 12: Threat Score Bounds

For any combination of velocity, geo, device, credential stuffing, and Tor signal scores, the composite Threat_Score computed by the UEBA_Engine SHALL always be in the range [0.0, 1.0].

**Validates: Requirements 11.1, 11.8**

---

### Property 13: Bcrypt Rounds Floor

For any server load score in [0.0, 1.0], the adaptive Bcrypt_Rounds value returned by the calibration engine SHALL always be greater than or equal to 10.

**Validates: Requirements 16.1, 16.2**

---

### Property 14: Idempotency Consistency

For any two requests with the same `X-Idempotency-Key`, the response body SHALL be identical and the second response SHALL carry the header `X-Idempotency-Replayed: true`.

**Validates: Requirements 19.2, 19.5**

---

### Property 15: Distributed Lock Exclusivity

For any lock key, at most one process SHALL hold the lock at any point in time — concurrent acquisition attempts SHALL result in exactly one success and all others receiving a conflict error.

**Validates: Requirements 14.1, 14.6**

---

### Property 16: Tenant Isolation

For any query executed with tenantId=A, every row in the result set SHALL have `tenant_id = A` — no row belonging to any other tenant SHALL appear in the results.

**Validates: Requirements 1.1, 1.2, 1.3**

---

### Property 17: Credential Pepper Consistency

For any valid password and the configured pepper, verifying the password against its hash SHALL return true. Verifying the same password against a hash produced with a different pepper SHALL return false.

**Validates: Requirements 2.9, 31.5**

---

### Property 18: Event Store Ordering

For any aggregate, loading its events from the event store SHALL return them in strictly ascending `aggregate_seq` order — for all indices i < j, `events[i].aggregateSeq < events[j].aggregateSeq`.

**Validates: Requirements 18.1, 18.2**

---

### Property 19: Outbox At-Least-Once Delivery

For any Outbox_Event inserted into the `outbox_events` table, there SHALL exist a future point in time at which the event's status is either `PUBLISHED` or `DLQ` — no event SHALL remain in `PENDING` status indefinitely.

**Validates: Requirements 17.6**

---

### Property 20: ABAC JIT Determinism

For any ABAC_Policy condition and any evaluation context, the result of the JIT-compiled function SHALL equal the result of the DSL interpreter: `compiledFn(policy)(context) = interpretDsl(policy.condition)(context)`.

**Validates: Requirements 9.7**


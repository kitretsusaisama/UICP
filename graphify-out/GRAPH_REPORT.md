# Graph Report - .  (2026-05-10)

## Corpus Check
- Large corpus: 405 files · ~123,448 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder, or use --no-semantic to run AST-only.

## Summary
- 1868 nodes · 2813 edges · 189 communities detected
- Extraction: 84% EXTRACTED · 16% INFERRED · 0% AMBIGUOUS · INFERRED: 441 edges (avg confidence: 0.5)
- Token cost: 12,184 input · 17,693 output

## God Nodes (most connected - your core abstractions)
1. `User` - 30 edges
2. `AuthController` - 19 edges
3. `Session` - 18 edges
4. `RedisCacheAdapter` - 17 edges
5. `Identity` - 15 edges
6. `parseTenantId()` - 15 edges
7. `TokenService` - 15 edges
8. `SessionService` - 14 edges
9. `InMemoryRedisClient` - 14 edges
10. `RedisSessionStore` - 14 edges

## Surprising Connections (you probably didn't know these)
- `UICP System` --implements--> `ABAC JIT Compiler`  [EXTRACTED]
  UICP_API_INVENTORY/full_api_inventory.md → UICP_AUDIT/uicp_audit_report.md
- `Forever Blocked Race` --rationale_for--> `Lua Script Atomic Token Bucket`  [INFERRED]
  UICP_AUDIT/uicp_audit_report.md → UICP_AUDIT/uicp_reconstruction_plan.md
- `Audit Log Integrity Bypass` --rationale_for--> `Immutable Audit Ledger`  [INFERRED]
  UICP_AUDIT/uicp_audit_report.md → UICP_AUDIT/uicp_reconstruction_plan.md
- `Phase 0 - Declare System Invalid` --references--> `ABAC JIT Compiler`  [EXTRACTED]
  UICP_AUDIT/uicp_reconstruction_plan.md → UICP_AUDIT/uicp_audit_report.md
- `Phase 3 - Economic Warfare Defense` --rationale_for--> `SMS Pumping Attack`  [EXTRACTED]
  UICP_AUDIT/uicp_reconstruction_plan.md → UICP_AUDIT/uicp_audit_report.md

## Hyperedges (group relationships)
- **Authentication Handler Data Flow** — signup_handler, login_handler, refresh_token_handler, logout_handler, token_service, session_service [EXTRACTED 1.00]
- **UEBA Analysis Pipeline** — ueba_engine, velocity_analyzer, geo_analyzer, credential_stuffing_analyzer [EXTRACTED 1.00]
- **Attack Surface Analysis** — abac_rce_attack, sms_pumping_attack, forever_blocked_race, redis_outage_failure, mysql_replication_lag_failure, audit_log_integrity_bypass, token_secret_exposure [EXTRACTED 1.00]

## Communities

### Community 0 - "Core Application & Auth"
Cohesion: 0.04
Nodes (36): buildAdapter(), makeAdapter(), ApplicationModule, AuthPolicyDomainService, DomainException, GetUserSessionsQuery, createApp(), makeConfigService() (+28 more)

### Community 1 - "Module Bootstrap & Workers"
Cohesion: 0.02
Nodes (21): AppModule, AuditExportWorker, AuditWriteWorker, AuthGrpcHandler, CacheModule, ConfigModule, EmailSendWorker, EncryptionModule (+13 more)

### Community 2 - "HTTP Controllers & Interceptors"
Cohesion: 0.03
Nodes (25): AdminController, ClsContextInterceptor, CoreController, DeprecatedApiInterceptor, DynamicModuleController, parseTenantId(), validateFields(), ExtensionController (+17 more)

### Community 3 - "SDK Client & Hooks"
Cohesion: 0.03
Nodes (22): UicpClient, useAuditStream(), useAuth(), useCommunication(), useOtp(), useProviderHealth(), useProviders(), useQueues() (+14 more)

### Community 4 - "ABAC Policy Engine"
Cohesion: 0.04
Nodes (13): AbacCondition, compare(), evaluateNode(), resolveAttribute(), resolveValue(), tokenize(), AbacPolicyDomainService, AbacJitCompiler (+5 more)

### Community 5 - "Notification & OTP Providers"
Cohesion: 0.05
Nodes (11): MailerooEmailProvider, Msg91SmsProvider, NotificationDispatcherService, NotificationTemplateService, OtpModule, parseTenantId(), PlatformController, ProviderRegistryService (+3 more)

### Community 6 - "Resilience & Circuit Breaker"
Cohesion: 0.05
Nodes (13): CircuitBreaker, CredentialStuffingAnalyzer, DeviceAnalyzer, GeoAnalyzer, MaxmindGeoAdapter, makeAnalyzerWithCounts(), makeBaselineCache(), makeCache() (+5 more)

### Community 7 - "Governance & SOC Repositories"
Cohesion: 0.04
Nodes (11): MysqlIncidentRepository, MysqlManifestRepository, uuidToBuffer(), MysqlRoleAssignmentRepository, MysqlRoleRepository, MysqlSocAlertRepository, RepositoriesModule, RoleAssignment (+3 more)

### Community 8 - "Platform & App Management"
Cohesion: 0.04
Nodes (8): AppController, App, AppService, MysqlAppRepository, MysqlWebhookRepository, WebhookController, Webhook, WebhookService

### Community 9 - "Domain Events"
Cohesion: 0.04
Nodes (20): LoginFailedEvent, LoginSucceededEvent, OtpVerifiedEvent, ThreatDetectedEvent, TokenRefreshedEvent, TokenReuseDetectedEvent, InMemoryEventStore, bufferToUuid() (+12 more)

### Community 10 - "MySQL Repositories"
Cohesion: 0.07
Nodes (15): bufferToUuid(), MysqlAbacPolicyRepository, policyCacheKey(), rowToPolicy(), uuidToBuffer(), MysqlModule, bufferToUuid(), MysqlOutboxRepository (+7 more)

### Community 11 - "Adaptive Infrastructure"
Cohesion: 0.05
Nodes (7): AdaptiveCacheService, HitRateTracker, AdaptiveDbPoolService, AdaptiveQueueConcurrencyService, AdaptiveRateLimitService, AdaptiveTuningEngine, ThresholdTuner

### Community 12 - "Query Handlers & Audit"
Cohesion: 0.05
Nodes (11): GetUserQuery, ListAuditLogsHandler, ListAuditLogsQuery, computeChecksum(), InMemoryAuditLogRepository, MysqlAuditLogRepository, uuidToBuffer(), SchemaValidationException (+3 more)

### Community 13 - "Distributed Locks"
Cohesion: 0.06
Nodes (7): InMemoryRateLimiter, LockModule, MysqlAdvisoryLock, RedisLockAdapter, InMemoryRedisClient, ResilienceModule, RetryBudget

### Community 14 - "Communication Runtime"
Cohesion: 0.07
Nodes (9): CommunicationController, tenantId(), CommunicationRuntime, toOtpPurpose(), EmailRuntime, ProviderHealthRuntime, TenantProviderResolver, toOtpPurpose() (+1 more)

### Community 15 - "Community 15"
Cohesion: 0.07
Nodes (6): DnsAdapter, DnsModule, DomainController, Domain, DomainService, MysqlDomainRepository

### Community 16 - "Community 16"
Cohesion: 0.09
Nodes (1): User

### Community 17 - "Community 17"
Cohesion: 0.09
Nodes (5): OtelSpan, OtelTracerAdapter, SlowRequestSpanProcessor, UicpSampler, TracingModule

### Community 18 - "Community 18"
Cohesion: 0.1
Nodes (5): ExtensionExecutorService, ExtensionRegistryService, ExtensionsController, ExtensionsExecutionController, ExtensionsModule

### Community 19 - "Community 19"
Cohesion: 0.18
Nodes (4): AuthController, getClientIp(), hashIp(), parseTenantId()

### Community 20 - "Community 20"
Cohesion: 0.14
Nodes (2): AdaptiveBcrypt, ServerLoadMonitor

### Community 21 - "Community 21"
Cohesion: 0.16
Nodes (3): MetricsController, MetricsModule, PromClientMetricsAdapter

### Community 22 - "Community 22"
Cohesion: 0.12
Nodes (1): Session

### Community 23 - "Community 23"
Cohesion: 0.12
Nodes (0): 

### Community 24 - "Community 24"
Cohesion: 0.2
Nodes (1): RedisCacheAdapter

### Community 25 - "Community 25"
Cohesion: 0.12
Nodes (14): ABAC JIT Compiler, ABAC JIT RCE Attack, Audit Log Integrity Bypass, FirebaseOtpAdapter, Forever Blocked Race, Immutable Audit Ledger, Lua Script Atomic Token Bucket, OPA Policy Engine (+6 more)

### Community 26 - "Community 26"
Cohesion: 0.13
Nodes (1): Identity

### Community 27 - "Community 27"
Cohesion: 0.15
Nodes (1): SessionService

### Community 28 - "Community 28"
Cohesion: 0.29
Nodes (6): bufferToUuid(), identityTypeToDb(), mapIdentityType(), MysqlIdentityRepository, rowToIdentity(), uuidToBuffer()

### Community 29 - "Community 29"
Cohesion: 0.18
Nodes (3): identityTypeToDb(), MysqlUserRepository, uuidToBuffer()

### Community 30 - "Community 30"
Cohesion: 0.21
Nodes (1): InMemoryRedisClient

### Community 31 - "Community 31"
Cohesion: 0.33
Nodes (1): RedisSessionStore

### Community 32 - "Community 32"
Cohesion: 0.21
Nodes (1): InMemoryRedisClient

### Community 33 - "Community 33"
Cohesion: 0.19
Nodes (4): ExtensionDispatcherService, bufferToUuid(), MysqlExtensionBindingRepository, uuidToBuffer()

### Community 34 - "Community 34"
Cohesion: 0.46
Nodes (1): Parser

### Community 35 - "Community 35"
Cohesion: 0.29
Nodes (1): Aes256GcmEncryptionAdapter

### Community 36 - "Community 36"
Cohesion: 0.26
Nodes (2): InMemoryTokenBucket, RateLimiterMiddleware

### Community 37 - "Community 37"
Cohesion: 0.33
Nodes (1): DistributedLockService

### Community 38 - "Community 38"
Cohesion: 0.27
Nodes (4): bufferToUuid(), MysqlAlertRepository, rowToAlert(), uuidToBuffer()

### Community 39 - "Community 39"
Cohesion: 0.27
Nodes (1): OutboxRelayWorker

### Community 40 - "Community 40"
Cohesion: 0.36
Nodes (1): UebaEngine

### Community 41 - "Community 41"
Cohesion: 0.22
Nodes (1): MysqlSessionFallback

### Community 42 - "Community 42"
Cohesion: 0.36
Nodes (1): BullMqQueueAdapter

### Community 43 - "Community 43"
Cohesion: 0.22
Nodes (1): PipelineMock

### Community 44 - "Community 44"
Cohesion: 0.22
Nodes (1): PipelineMock

### Community 45 - "Community 45"
Cohesion: 0.46
Nodes (7): acquireAdvisoryLock(), applyMigration(), ensureSchemaVersionsTable(), getAppliedMigrations(), loadMigrationFiles(), releaseAdvisoryLock(), runMigrations()

### Community 46 - "Community 46"
Cohesion: 0.32
Nodes (1): GovernanceBootstrapValidator

### Community 47 - "Community 47"
Cohesion: 0.36
Nodes (3): parseTenantId(), parseTenantIdVo(), SessionController

### Community 48 - "Community 48"
Cohesion: 0.48
Nodes (1): IdentityVerificationSaga

### Community 49 - "Community 49"
Cohesion: 0.43
Nodes (1): OtpService

### Community 50 - "Community 50"
Cohesion: 0.29
Nodes (1): RuntimeIdentityService

### Community 51 - "Community 51"
Cohesion: 0.29
Nodes (1): Email

### Community 52 - "Community 52"
Cohesion: 0.33
Nodes (1): IdentityId

### Community 53 - "Community 53"
Cohesion: 0.33
Nodes (1): SessionId

### Community 54 - "Community 54"
Cohesion: 0.33
Nodes (1): TenantId

### Community 55 - "Community 55"
Cohesion: 0.33
Nodes (1): UserId

### Community 56 - "Community 56"
Cohesion: 0.43
Nodes (2): InMemoryUserRepositoryWithOptimisticLock, makeUpdate()

### Community 57 - "Community 57"
Cohesion: 0.29
Nodes (1): SkipLockedOutboxRepository

### Community 58 - "Community 58"
Cohesion: 0.48
Nodes (1): UicpLogger

### Community 59 - "Community 59"
Cohesion: 0.53
Nodes (1): IdempotencyService

### Community 60 - "Community 60"
Cohesion: 0.33
Nodes (1): OAuthService

### Community 61 - "Community 61"
Cohesion: 0.33
Nodes (1): Device

### Community 62 - "Community 62"
Cohesion: 0.33
Nodes (1): PhoneNumber

### Community 63 - "Community 63"
Cohesion: 0.33
Nodes (1): ConcurrentIdentityRepository

### Community 64 - "Community 64"
Cohesion: 0.33
Nodes (1): InMemoryIdentityRepository

### Community 65 - "Community 65"
Cohesion: 0.53
Nodes (1): GlobalExceptionFilter

### Community 66 - "Community 66"
Cohesion: 0.4
Nodes (1): TorExitNodeChecker

### Community 67 - "Community 67"
Cohesion: 0.4
Nodes (1): User

### Community 68 - "Community 68"
Cohesion: 0.4
Nodes (1): ConcurrentUserRepository

### Community 69 - "Community 69"
Cohesion: 0.4
Nodes (1): InMemoryUserRepository

### Community 70 - "Community 70"
Cohesion: 0.4
Nodes (2): GovernanceGuard, GovernanceModule

### Community 71 - "Community 71"
Cohesion: 0.5
Nodes (1): LoginHandler

### Community 72 - "Community 72"
Cohesion: 0.5
Nodes (1): SignupEmailHandler

### Community 73 - "Community 73"
Cohesion: 0.5
Nodes (1): SignupPhoneHandler

### Community 74 - "Community 74"
Cohesion: 0.67
Nodes (1): GetJwksHandler

### Community 75 - "Community 75"
Cohesion: 0.5
Nodes (1): JwksController

### Community 76 - "Community 76"
Cohesion: 0.5
Nodes (1): ClientBasicAuthGuard

### Community 77 - "Community 77"
Cohesion: 0.5
Nodes (1): InMemoryTokenBucket

### Community 78 - "Community 78"
Cohesion: 0.67
Nodes (1): LogoutHandler

### Community 79 - "Community 79"
Cohesion: 0.67
Nodes (1): LogoutAllHandler

### Community 80 - "Community 80"
Cohesion: 0.67
Nodes (1): OAuthCallbackHandler

### Community 81 - "Community 81"
Cohesion: 0.67
Nodes (1): RotateKeysCommand

### Community 82 - "Community 82"
Cohesion: 0.67
Nodes (1): RotateKeysHandler

### Community 83 - "Community 83"
Cohesion: 0.67
Nodes (1): VerifyOtpHandler

### Community 84 - "Community 84"
Cohesion: 0.67
Nodes (1): DynamicCommandRegistryService

### Community 85 - "Community 85"
Cohesion: 0.67
Nodes (1): GetThreatHistoryHandler

### Community 86 - "Community 86"
Cohesion: 0.67
Nodes (1): GetThreatHistoryQuery

### Community 87 - "Community 87"
Cohesion: 0.67
Nodes (1): GetUserHandler

### Community 88 - "Community 88"
Cohesion: 0.67
Nodes (1): GetUserSessionsHandler

### Community 89 - "Community 89"
Cohesion: 0.67
Nodes (1): RuntimeAuthorizationService

### Community 90 - "Community 90"
Cohesion: 0.67
Nodes (1): AdminUserService

### Community 91 - "Community 91"
Cohesion: 0.67
Nodes (1): AuditService

### Community 92 - "Community 92"
Cohesion: 0.67
Nodes (1): KmsService

### Community 93 - "Community 93"
Cohesion: 0.67
Nodes (1): SocService

### Community 94 - "Community 94"
Cohesion: 0.67
Nodes (1): AuthenticationException

### Community 95 - "Community 95"
Cohesion: 0.67
Nodes (1): InfrastructureException

### Community 96 - "Community 96"
Cohesion: 0.67
Nodes (1): IdempotencyInterceptor

### Community 97 - "Community 97"
Cohesion: 0.67
Nodes (0): 

### Community 98 - "Community 98"
Cohesion: 0.67
Nodes (3): KMS Secrets Management, Phase 6 - Security Hard Reset, Token Secret Exposure

### Community 99 - "Community 99"
Cohesion: 1.0
Nodes (0): 

### Community 100 - "Community 100"
Cohesion: 1.0
Nodes (0): 

### Community 101 - "Community 101"
Cohesion: 1.0
Nodes (0): 

### Community 102 - "Community 102"
Cohesion: 1.0
Nodes (0): 

### Community 103 - "Community 103"
Cohesion: 1.0
Nodes (0): 

### Community 104 - "Community 104"
Cohesion: 1.0
Nodes (0): 

### Community 105 - "Community 105"
Cohesion: 1.0
Nodes (0): 

### Community 106 - "Community 106"
Cohesion: 1.0
Nodes (0): 

### Community 107 - "Community 107"
Cohesion: 1.0
Nodes (0): 

### Community 108 - "Community 108"
Cohesion: 1.0
Nodes (0): 

### Community 109 - "Community 109"
Cohesion: 1.0
Nodes (0): 

### Community 110 - "Community 110"
Cohesion: 1.0
Nodes (0): 

### Community 111 - "Community 111"
Cohesion: 1.0
Nodes (0): 

### Community 112 - "Community 112"
Cohesion: 1.0
Nodes (0): 

### Community 113 - "Community 113"
Cohesion: 1.0
Nodes (0): 

### Community 114 - "Community 114"
Cohesion: 1.0
Nodes (0): 

### Community 115 - "Community 115"
Cohesion: 1.0
Nodes (0): 

### Community 116 - "Community 116"
Cohesion: 1.0
Nodes (1): GetJwksQuery

### Community 117 - "Community 117"
Cohesion: 1.0
Nodes (1): DatabaseModule

### Community 118 - "Community 118"
Cohesion: 1.0
Nodes (1): ClsModule

### Community 119 - "Community 119"
Cohesion: 1.0
Nodes (0): 

### Community 120 - "Community 120"
Cohesion: 1.0
Nodes (2): Phase 9 - 2027 Survival Design, WebAuthn Passkeys

### Community 121 - "Community 121"
Cohesion: 1.0
Nodes (0): 

### Community 122 - "Community 122"
Cohesion: 1.0
Nodes (0): 

### Community 123 - "Community 123"
Cohesion: 1.0
Nodes (0): 

### Community 124 - "Community 124"
Cohesion: 1.0
Nodes (0): 

### Community 125 - "Community 125"
Cohesion: 1.0
Nodes (0): 

### Community 126 - "Community 126"
Cohesion: 1.0
Nodes (0): 

### Community 127 - "Community 127"
Cohesion: 1.0
Nodes (0): 

### Community 128 - "Community 128"
Cohesion: 1.0
Nodes (0): 

### Community 129 - "Community 129"
Cohesion: 1.0
Nodes (0): 

### Community 130 - "Community 130"
Cohesion: 1.0
Nodes (0): 

### Community 131 - "Community 131"
Cohesion: 1.0
Nodes (0): 

### Community 132 - "Community 132"
Cohesion: 1.0
Nodes (0): 

### Community 133 - "Community 133"
Cohesion: 1.0
Nodes (0): 

### Community 134 - "Community 134"
Cohesion: 1.0
Nodes (0): 

### Community 135 - "Community 135"
Cohesion: 1.0
Nodes (0): 

### Community 136 - "Community 136"
Cohesion: 1.0
Nodes (0): 

### Community 137 - "Community 137"
Cohesion: 1.0
Nodes (0): 

### Community 138 - "Community 138"
Cohesion: 1.0
Nodes (0): 

### Community 139 - "Community 139"
Cohesion: 1.0
Nodes (0): 

### Community 140 - "Community 140"
Cohesion: 1.0
Nodes (0): 

### Community 141 - "Community 141"
Cohesion: 1.0
Nodes (0): 

### Community 142 - "Community 142"
Cohesion: 1.0
Nodes (0): 

### Community 143 - "Community 143"
Cohesion: 1.0
Nodes (0): 

### Community 144 - "Community 144"
Cohesion: 1.0
Nodes (0): 

### Community 145 - "Community 145"
Cohesion: 1.0
Nodes (0): 

### Community 146 - "Community 146"
Cohesion: 1.0
Nodes (0): 

### Community 147 - "Community 147"
Cohesion: 1.0
Nodes (0): 

### Community 148 - "Community 148"
Cohesion: 1.0
Nodes (0): 

### Community 149 - "Community 149"
Cohesion: 1.0
Nodes (0): 

### Community 150 - "Community 150"
Cohesion: 1.0
Nodes (0): 

### Community 151 - "Community 151"
Cohesion: 1.0
Nodes (0): 

### Community 152 - "Community 152"
Cohesion: 1.0
Nodes (0): 

### Community 153 - "Community 153"
Cohesion: 1.0
Nodes (0): 

### Community 154 - "Community 154"
Cohesion: 1.0
Nodes (0): 

### Community 155 - "Community 155"
Cohesion: 1.0
Nodes (0): 

### Community 156 - "Community 156"
Cohesion: 1.0
Nodes (0): 

### Community 157 - "Community 157"
Cohesion: 1.0
Nodes (0): 

### Community 158 - "Community 158"
Cohesion: 1.0
Nodes (0): 

### Community 159 - "Community 159"
Cohesion: 1.0
Nodes (0): 

### Community 160 - "Community 160"
Cohesion: 1.0
Nodes (0): 

### Community 161 - "Community 161"
Cohesion: 1.0
Nodes (0): 

### Community 162 - "Community 162"
Cohesion: 1.0
Nodes (0): 

### Community 163 - "Community 163"
Cohesion: 1.0
Nodes (0): 

### Community 164 - "Community 164"
Cohesion: 1.0
Nodes (0): 

### Community 165 - "Community 165"
Cohesion: 1.0
Nodes (0): 

### Community 166 - "Community 166"
Cohesion: 1.0
Nodes (0): 

### Community 167 - "Community 167"
Cohesion: 1.0
Nodes (0): 

### Community 168 - "Community 168"
Cohesion: 1.0
Nodes (0): 

### Community 169 - "Community 169"
Cohesion: 1.0
Nodes (0): 

### Community 170 - "Community 170"
Cohesion: 1.0
Nodes (0): 

### Community 171 - "Community 171"
Cohesion: 1.0
Nodes (0): 

### Community 172 - "Community 172"
Cohesion: 1.0
Nodes (0): 

### Community 173 - "Community 173"
Cohesion: 1.0
Nodes (0): 

### Community 174 - "Community 174"
Cohesion: 1.0
Nodes (0): 

### Community 175 - "Community 175"
Cohesion: 1.0
Nodes (0): 

### Community 176 - "Community 176"
Cohesion: 1.0
Nodes (0): 

### Community 177 - "Community 177"
Cohesion: 1.0
Nodes (0): 

### Community 178 - "Community 178"
Cohesion: 1.0
Nodes (0): 

### Community 179 - "Community 179"
Cohesion: 1.0
Nodes (0): 

### Community 180 - "Community 180"
Cohesion: 1.0
Nodes (0): 

### Community 181 - "Community 181"
Cohesion: 1.0
Nodes (0): 

### Community 182 - "Community 182"
Cohesion: 1.0
Nodes (0): 

### Community 183 - "Community 183"
Cohesion: 1.0
Nodes (1): Phase 4 - Failure Mode Dominance

### Community 184 - "Community 184"
Cohesion: 1.0
Nodes (1): Phase 5 - Temporal Consistency Control

### Community 185 - "Community 185"
Cohesion: 1.0
Nodes (1): Phase 7 - SOC and Detection

### Community 186 - "Community 186"
Cohesion: 1.0
Nodes (1): Phase 8 - Codebase Purge

### Community 187 - "Community 187"
Cohesion: 1.0
Nodes (1): Phase 11 - Validation Under Attack

### Community 188 - "Community 188"
Cohesion: 1.0
Nodes (1): Phase 12 - Final Verdict

## Knowledge Gaps
- **33 isolated node(s):** `AppModule`, `ApplicationModule`, `GetJwksQuery`, `CacheModule`, `DatabaseModule` (+28 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 99`** (2 nodes): `AuditEventStream.tsx`, `AuditEventStream()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 100`** (2 nodes): `CorrelationInspector.tsx`, `CorrelationInspector()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 101`** (2 nodes): `DeadLetterInspector.tsx`, `DeadLetterInspector()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 102`** (2 nodes): `ReplayTimeline.tsx`, `ReplayTimeline()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 103`** (2 nodes): `TenantIsolationBadge.tsx`, `TenantIsolationBadge()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 104`** (2 nodes): `WebhookEventViewer.tsx`, `WebhookEventViewer()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 105`** (2 nodes): `OtpChallengeState.tsx`, `OtpChallengeState()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 106`** (2 nodes): `OtpChannels.tsx`, `OtpChannels()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 107`** (2 nodes): `OtpInput.tsx`, `OtpInput()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 108`** (2 nodes): `OtpProvider.tsx`, `OtpProvider()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 109`** (2 nodes): `OtpProviderFallbackBanner.tsx`, `OtpProviderFallbackBanner()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 110`** (2 nodes): `OtpResend.tsx`, `OtpResend()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 111`** (2 nodes): `OtpTimer.tsx`, `OtpTimer()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 112`** (2 nodes): `OtpWidget.tsx`, `OtpWidget()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 113`** (2 nodes): `apply-governance.js`, `applyDecorator()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 114`** (2 nodes): `enforce-release-gates.ts`, `walkDir()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 115`** (2 nodes): `generate-manifest.ts`, `walkDir()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 116`** (2 nodes): `get-jwks.query.ts`, `GetJwksQuery`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 117`** (2 nodes): `database.module.ts`, `DatabaseModule`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 118`** (2 nodes): `cls.module.ts`, `ClsModule`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 119`** (2 nodes): `tenant-factory.ts`, `tenantFixture()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 120`** (2 nodes): `Phase 9 - 2027 Survival Design`, `WebAuthn Passkeys`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 121`** (1 nodes): `next-env.d.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 122`** (1 nodes): `tailwind.config.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 123`** (1 nodes): `enforce-opa-policies.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 124`** (1 nodes): `fix-audit-export-query.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 125`** (1 nodes): `fix-auth-guards.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 126`** (1 nodes): `fix-bullmq-len.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 127`** (1 nodes): `fix-extension-executor-rsa.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 128`** (1 nodes): `fix-extension-executor.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 129`** (1 nodes): `fix-misc-bugs.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 130`** (1 nodes): `fix-oauth.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 131`** (1 nodes): `fix-otp-ttl.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 132`** (1 nodes): `fix-otp-worker-redis.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 133`** (1 nodes): `repair-oauth.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 134`** (1 nodes): `update-auth-controller-otp.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 135`** (1 nodes): `update-bootstrap.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 136`** (1 nodes): `update-metrics.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 137`** (1 nodes): `update-otp-fingerprint.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 138`** (1 nodes): `update-otp-service.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 139`** (1 nodes): `cache-invalidation-race.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 140`** (1 nodes): `concurrent-otp-verify.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 141`** (1 nodes): `concurrent-refresh.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 142`** (1 nodes): `provider-fallback-race.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 143`** (1 nodes): `tenant-queue-fairness.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 144`** (1 nodes): `communication-runtime.contract.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 145`** (1 nodes): `tenant-providers.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 146`** (1 nodes): `auth-login.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 147`** (1 nodes): `otp-widget.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 148`** (1 nodes): `provider-health.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 149`** (1 nodes): `queue-dead-letter.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 150`** (1 nodes): `security-replay.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 151`** (1 nodes): `session-lineage.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 152`** (1 nodes): `auth-communication.integration.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 153`** (1 nodes): `provider-transaction-rollback.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 154`** (1 nodes): `auth-runtime-latency.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 155`** (1 nodes): `maileroo-email.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 156`** (1 nodes): `msg91-direct-otp.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 157`** (1 nodes): `provider-circuit-breaker.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 158`** (1 nodes): `provider-fallback.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 159`** (1 nodes): `provider-resolution.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 160`** (1 nodes): `provider-webhooks.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 161`** (1 nodes): `resend-email.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 162`** (1 nodes): `tenant-cache-isolation.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 163`** (1 nodes): `production-bugs.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 164`** (1 nodes): `auth-runtime.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 165`** (1 nodes): `edge-validation.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 166`** (1 nodes): `error-contract.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 167`** (1 nodes): `next-middleware.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 168`** (1 nodes): `otp-runtime.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 169`** (1 nodes): `realtime-sync.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 170`** (1 nodes): `refresh-singleflight.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 171`** (1 nodes): `jwt-forgery.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 172`** (1 nodes): `otp-replay.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 173`** (1 nodes): `provider-key-isolation.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 174`** (1 nodes): `queue-poisoning.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 175`** (1 nodes): `refresh-replay.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 176`** (1 nodes): `sender-spoofing.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 177`** (1 nodes): `tenant-breakout.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 178`** (1 nodes): `webhook-signature.spec.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 179`** (1 nodes): `fake-maileroo.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 180`** (1 nodes): `fake-msg91.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 181`** (1 nodes): `fake-resend.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 182`** (1 nodes): `test-app.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 183`** (1 nodes): `Phase 4 - Failure Mode Dominance`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 184`** (1 nodes): `Phase 5 - Temporal Consistency Control`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 185`** (1 nodes): `Phase 7 - SOC and Detection`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 186`** (1 nodes): `Phase 8 - Codebase Purge`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 187`** (1 nodes): `Phase 11 - Validation Under Attack`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 188`** (1 nodes): `Phase 12 - Final Verdict`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `User` connect `Community 16` to `Core Application & Auth`?**
  _High betweenness centrality (0.026) - this node is a cross-community bridge._
- **Why does `Session` connect `Community 22` to `Core Application & Auth`?**
  _High betweenness centrality (0.016) - this node is a cross-community bridge._
- **Why does `RedisCacheAdapter` connect `Community 24` to `Core Application & Auth`?**
  _High betweenness centrality (0.015) - this node is a cross-community bridge._
- **What connects `AppModule`, `ApplicationModule`, `GetJwksQuery` to the rest of the system?**
  _33 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Core Application & Auth` be split into smaller, more focused modules?**
  _Cohesion score 0.04 - nodes in this community are weakly interconnected._
- **Should `Module Bootstrap & Workers` be split into smaller, more focused modules?**
  _Cohesion score 0.02 - nodes in this community are weakly interconnected._
- **Should `HTTP Controllers & Interceptors` be split into smaller, more focused modules?**
  _Cohesion score 0.03 - nodes in this community are weakly interconnected._
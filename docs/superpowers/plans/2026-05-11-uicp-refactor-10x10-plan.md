# UICP Refactoring Plan: 6.8/10 → 10/10

## Context

CTO benchmark assessment (2026-05-11) found these critical gaps:
- No Helmet/CORS security headers in main.ts
- 8 files using console.log instead of Pino (circuit-breaker, migration-runner, queue-backpressure guard, msg91 provider, etc.)
- auth.controller.ts is a 679-line God class handling 14+ endpoint groups
- Zero DTO files — inline Zod schemas used for both validation AND response shaping
- UUID→Buffer conversion duplicated across 15+ MySQL repositories
- No health check endpoint
- Error responses not consistently mapped to HTTP status codes
- No API versioning strategy

**Allowed APIs confirmed from codebase:**
- `UicpLogger` (src/shared/logger/pino-logger.service.ts:17) — CLS-aware structured logger with redact paths
- `Logger` from @nestjs/common — fallback, less preferred
- `ZodValidationPipe` (src/interface/http/pipes/zod-validation.pipe.ts:20) — validated pipe pattern
- `ResponseEnvelopeInterceptor` — wraps responses in { success, data, meta }
- `GlobalExceptionFilter` — maps exceptions to HTTP with structured error codes
- `MYSQL_POOL`, `DbPool`, `DbConnection` from mysql.module.ts:28-32
- `CircuitBreaker` class from circuit-breaker.ts:76
- `DB_TRANSACTION` / `TransactionFactory` from mysql.module.ts:38-40

---

## Phase 0: Documentation Discovery (Verification Only)

No new documentation discovery needed — all patterns already verified from source files read above.

**Known patterns to follow:**
- `UicpLogger` injection: constructor(`@Inject(UicpLogger) private readonly logger: UicpLogger`)
- Logger usage: `this.logger.warn(message, context, extra)`
- ZodValidationPipe: `@Body(new ZodValidationPipe(schema))`
- Response envelope: Controller returns `{ data: ... }` or raw body, interceptor wraps it
- MySQL module exports: `MYSQL_POOL`, `DB_TRANSACTION`

---

## Phase 1: P0 — Critical Security & Production Hygiene

### 1.1 Add Helmet.js and CORS to main.ts

**Files to modify:**
- `src/main.ts`

**What to do:**
1. Install helmet: `npm install helmet` (check if already in deps — grep package.json)
2. Install cors: `npm install cors` (check if already in deps)
3. Add after `app.useLogger(logger)` and before swagger setup:

```typescript
import helmet from 'helmet';
import cors from 'cors';

// After app creation, before listen:
app.use(helmet());
app.use(cors({
  origin: process.env['CORS_ORIGINS']?.split(',') ?? false,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-tenant-id', 'x-request-id', 'x-idempotency-key'],
}));
```

**Verification:**
- `grep -rn "helmet\|cors" src/main.ts`
- Ensure no existing helmet/cors calls in main.ts

**Anti-patterns:**
- Do NOT use `app.enableCors()` — use explicit config instead
- Do NOT add helmet before error handlers — add after `useLogger`

---

### 1.2 Replace console.log with Pino Logger in Infrastructure Files

**Files to modify (8 files):**

1. `src/infrastructure/resilience/circuit-breaker.ts`
   - Import `UicpLogger` from `../../../shared/logger/pino-logger.service`
   - Replace `private readonly logger = new Logger(...)` with `@Inject(UicpLogger)`
   - Replace `console.log/warn/error` calls with `this.logger.warn/error/log`

2. `src/infrastructure/db/mysql/migration-runner.ts`
   - Add `UicpLogger` injection
   - Replace `console.log/warn/error` in migration-runner.ts with `this.logger.log/warn/error`
   - Migration output should be at `debug` level (verbose for ops, not user-facing)

3. `src/interface/http/guards/queue-backpressure.guard.ts`
   - Replace `console.warn` at line 35 with proper `Logger.warn`
   - Import `Logger` from @nestjs/common for the guard (or use `UicpLogger`)

4. `src/infrastructure/otp/kernel/providers/msg91-widget.provider.ts` — find and replace console.log
5. `src/infrastructure/otp/widgets/tenant-widget-config.service.ts` — find and replace console.log
6. `src/infrastructure/governance/bootstrap/governance.bootstrap.ts` — find and replace console.log
7. `src/infrastructure/db/mysql/database.module.ts` — find and replace console.log
8. `src/application/services/platform/webhook.service.ts` — find and replace console.log

**Verification:**
- `grep -rn "console\." src --include="*.ts" | grep -v spec | grep -v .d.ts`
- Should return zero results after this phase

**Anti-patterns:**
- Do NOT delete console calls — replace them with logger calls
- Do NOT use raw `Logger` from @nestjs/common if `UicpLogger` is available
- Do NOT add log calls that weren't there before — only replace existing ones

---

### 1.3 Split auth.controller.ts into Focused Controllers

**Files to create/modify:**

**New file: `src/interface/http/controllers/auth/signup.controller.ts`**
- Handles: `POST /v1/auth/signup`
- Move signupSchema, parseTenantId helper, signup handler from auth.controller.ts:232-261

**New file: `src/interface/http/controllers/auth/login.controller.ts`**
- Handles: `POST /v1/auth/login`, `POST /v1/auth/refresh`
- Move loginSchema, refreshSchema, login + refresh endpoints:265-303

**New file: `src/interface/http/controllers/auth/session.controller.ts`**
- Handles: `POST /v1/auth/logout`, `POST /v1/auth/logout-all`, `POST /v1/auth/actor/switch`
- Move logout/logoutAll/actorSwitch endpoints:305-439

**New file: `src/interface/http/controllers/auth/password.controller.ts`**
- Handles: `POST /v1/auth/password/change`, `POST /v1/auth/password/reset/request`, `POST /v1/auth/password/reset/confirm`
- Move changePasswordSchema, passwordResetRequestSchema, passwordResetConfirmSchema + endpoints:441-489

**New file: `src/interface/http/controllers/auth/oauth.controller.ts`**
- Handles: `GET /v1/auth/oauth/:provider`, `GET /v1/auth/oauth/:provider/callback`, `POST /v1/auth/oauth2/introspect`
- Move OAuth endpoints:491-607

**New file: `src/interface/http/controllers/auth/otp.controller.ts`**
- Handles: `POST /v1/auth/otp/send`, `POST /v1/auth/otp/verify`
- Move otpSendSchema, otpVerifySchema + endpoints:334-383

**File to modify: `src/interface/http/http.module.ts`**
- Replace single `AuthController` import with 6 new controllers
- Add all 6 to the `controllers` array

**Shared utilities to extract to `src/interface/http/controllers/auth/auth.helpers.ts`:**
- `parseTenantId()` — used by all 6 controllers
- `hashIp()` — used by login and oauth
- `getClientIp()` — used by login and oauth
- `AuthRequest` interface

**Helpers to keep in `auth.controller.ts` until all split:**
- `validateProvider()` — used only by oauth.controller.ts
- `buildOAuthUrl()` — used only by oauth.controller.ts
- `buildAuthResponse()` — used by login, oauth, session controllers

**Verification:**
- `ls src/interface/http/controllers/auth/` — should show 6 new controller files
- `wc -l src/interface/http/controllers/auth.controller.ts` — should be under 200 lines
- All 6 new controllers should have their own Logger instances

**Anti-patterns:**
- Do NOT create a new `AuthService` facade yet — that is P2 work
- Do NOT merge OTP routes from OtpWidgetController (src/interface/http/controllers/otp.controller.ts) — that's a separate widget controller
- Do NOT remove the @UseGuards decorator from protected endpoints
- Preserve all existing guards, interceptors, and decorators on each endpoint

---

## Phase 2: P1 — Health, DTOs, and Utilities

### 2.1 Add Health Check Endpoint

**File to create: `src/interface/http/controllers/health.controller.ts`**

```typescript
@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(
    @Inject(MYSQL_POOL) private readonly pool: DbPool,
    @Inject(INJECTION_TOKENS.CACHE_PORT) private readonly cache: ICachePort,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async check(): Promise<{ data: { status: string; checks: Record<string, string> } }> {
    const checks: Record<string, string> = {};
    let healthy = true;

    // MySQL check
    try {
      const [rows] = await this.pool.execute('SELECT 1 as ok');
      checks['mysql'] = 'ok';
    } catch {
      checks['mysql'] = 'fail';
      healthy = false;
    }

    // Redis check
    try {
      await this.cache.get('health-check');
      checks['redis'] = 'ok';
    } catch {
      checks['redis'] = 'fail';
      healthy = false;
    }

    return {
      data: {
        status: healthy ? 'healthy' : 'degraded',
        checks,
      },
    };
  }

  @Get('ready')
  @HttpCode(HttpStatus.OK)
  async ready(): Promise<{ data: { ready: boolean } }> {
    return { data: { ready: true } };
  }

  @Get('live')
  @HttpCode(HttpStatus.OK)
  async live(): Promise<{ data: { alive: boolean } }> {
    return { data: { alive: true } };
  }
}
```

**File to modify: `src/interface/http/http.module.ts`**
- Add `HealthController` to controllers array

**Verification:**
- `curl http://localhost:3000/health` should return JSON
- `curl http://localhost:3000/health/live` should return `{ alive: true }`

---

### 2.2 Create DTO Layer

**Directory: `src/interface/http/dto/`**

Create one file per existing controller, with Input/Request DTOs:

**`src/interface/http/dto/auth/`**
- `signup-email.input.dto.ts` — zod schema for signup email
- `signup-phone.input.dto.ts` — zod schema for signup phone
- `login.input.dto.ts` — zod schema for login
- `refresh.input.dto.ts` — zod schema for refresh token
- `otp-send.input.dto.ts` — zod schema for otp send
- `otp-verify.input.dto.ts` — zod schema for otp verify
- `password-change.input.dto.ts` — zod schema for password change
- `password-reset.input.dto.ts` — zod schema for password reset
- `oauth-introspect.input.dto.ts` — zod schema for introspection
- `auth.response.dto.ts` — shared response shapes (accessToken, refreshToken, principal, session)

**Pattern to follow — each DTO file:**
```typescript
import { z } from 'zod';

export const SignupEmailInputSchema = z.object({
  identityType: z.enum(['EMAIL', 'PHONE']).optional(),
  email: z.string().min(1).max(320),
  password: z.string().min(1).max(128),
});

export type SignupEmailInput = z.infer<typeof SignupEmailInputSchema>;
```

**Then in controllers, import from DTO layer:**
```typescript
import { SignupEmailInputSchema } from '../../dto/auth/signup-email.input.dto';
// Use: @Body(new ZodValidationPipe(SignupEmailInputSchema))
```

**Verification:**
- `ls src/interface/http/dto/auth/` — should have 10+ DTO files
- Controllers should import schemas from dto layer, not define inline
- After Phase 3, auth.controller.ts inline schemas should be removed

---

### 2.3 Centralize UUID-Buffer Utilities

**New file: `src/infrastructure/db/mysql/utils/uuid-buffer.ts`**

```typescript
/** Convert a UUID string to a 16-byte Buffer for BINARY(16) columns. */
export function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

/** Convert a 16-byte Buffer back to a UUID string. */
export function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
```

**Files to modify (replace inline uuidToBuffer/bufferToUuid with import):**
- `src/infrastructure/db/mysql/mysql-user.repository.ts` — replace lines 12-21
- `src/infrastructure/db/mysql/mysql-token.repository.ts`
- `src/infrastructure/db/mysql/mysql-session.repository.ts`
- `src/infrastructure/db/mysql/mysql-tenant.repository.ts`
- `src/infrastructure/db/mysql/mysql-identity.repository.ts`
- `src/infrastructure/db/mysql/mysql-otp-provider.repository.ts`
- `src/infrastructure/db/mysql/mysql-otp-widget.repository.ts`
- `src/infrastructure/db/mysql/mysql-otp-risk-policy.repository.ts`
- `src/infrastructure/db/mysql/mysql-otp-adaptive-model.repository.ts`
- `src/infrastructure/db/mysql/mysql-abac-policy.repository.ts`
- `src/infrastructure/db/mysql/mysql-audit-log.repository.ts`
- `src/infrastructure/db/mysql/mysql-runtime-identity.repository.ts`
- `src/infrastructure/db/mysql/mysql-event-store.repository.ts`
- `src/infrastructure/db/mysql/mysql-outbox.repository.ts`
- `src/infrastructure/db/mysql/repositories/platform/mysql-app.repository.ts`
- `src/infrastructure/db/mysql/repositories/platform/mysql-domain.repository.ts`
- `src/infrastructure/db/mysql/repositories/platform/mysql-webhook.repository.ts`
- `src/infrastructure/db/mysql/repositories/platform/mysql-app-secret.repository.ts`
- `src/infrastructure/db/mysql/repositories/governance/mysql-role.repository.ts`
- `src/infrastructure/db/mysql/repositories/governance/mysql-policy.repository.ts`
- `src/infrastructure/db/mysql/repositories/governance/mysql-role-assignment.repository.ts`

**Verification:**
- `grep -rn "function uuidToBuffer\|function bufferToUuid" src/infrastructure/db/mysql` — should return zero
- All repositories should import from `../../utils/uuid-buffer`

**Anti-patterns:**
- Do NOT change the conversion logic itself — only centralize the existing implementation
- Do NOT modify any SQL queries — only replace the helper functions

---

## Phase 3: P2 — API Versioning, Error Consistency, and Polish

### 3.1 Implement API Versioning Strategy

**Create: `src/interface/http/versioning.ts`**

Define deprecation markers for all routes:
- `VERSION_CURRENT = 'v1'` — active routes
- `VERSION_DEPRECATED = 'v0'` — routes being phased out
- `VERSION_EXPERIMENTAL = 'v2'` — new routes

**File to modify: `src/interface/http/http.module.ts`**
- Add `VersioningMiddleware` that checks for version prefix and sets appropriate headers
- Add `DeprecationHeaderInterceptor` that adds `Sunset` and `Deprecation` headers to deprecated routes

**Pattern:**
```typescript
// In deprecated controller
@ApiHeader({ name: 'Sunset', description: 'Sat, 31 Dec 2025 23:59:59 GMT' })
@ApiHeader({ name: 'Deprecation', description: 'Thu, 01 Jan 2026 00:00:00 GMT' })
```

**Verification:**
- `curl -I http://localhost:3000/v1/auth/login` — should show version headers
- Swagger docs should show version badges

---

### 3.2 Error Response Consistency — Create DomainException.toHttpStatus()

**File to modify: `src/domain/exceptions/domain.exception.ts`**

Add a `toHttpStatus()` method that maps DomainErrorCode to HTTP status:

```typescript
private static readonly STATUS_MAP: Record<DomainErrorCode, number> = {
  [DomainErrorCode.INVALID_EMAIL]: 400,
  [DomainErrorCode.INVALID_PHONE_NUMBER]: 400,
  [DomainErrorCode.WEAK_PASSWORD]: 400,
  [DomainErrorCode.COMMON_PASSWORD]: 400,
  [DomainErrorCode.INVALID_TENANT_ID]: 400,
  [DomainErrorCode.INVALID_USER_ID]: 400,
  [DomainErrorCode.INVALID_IDENTITY_ID]: 400,
  [DomainErrorCode.INVALID_SESSION_ID]: 400,
  [DomainErrorCode.INVALID_TOKEN_ID]: 400,
  [DomainErrorCode.CANNOT_ACTIVATE_WITHOUT_VERIFIED_IDENTITY]: 422,
  [DomainErrorCode.INVALID_STATUS_TRANSITION]: 422,
  [DomainErrorCode.MAX_IDENTITIES_PER_TYPE_EXCEEDED]: 422,
  [DomainErrorCode.IDENTITY_ALREADY_LINKED]: 409,
  [DomainErrorCode.IDENTITY_NOT_FOUND]: 404,
  [DomainErrorCode.INVALID_CREDENTIALS]: 401,
  [DomainErrorCode.IDENTITY_ALREADY_EXISTS]: 409,
  [DomainErrorCode.TOKEN_REVOKED]: 401,
  [DomainErrorCode.TOKEN_NOT_FOUND]: 404,
  // ... etc for all 30+ codes
};

toHttpStatus(): number {
  return DomainException.STATUS_MAP[this.errorCode] ?? 422;
}
```

**Update `src/interface/http/filters/global-exception.filter.ts`**
- Use `DomainException.toHttpStatus()` instead of hardcoded `422`

**Verification:**
- Every DomainErrorCode should have exactly one HTTP status
- No generic `throw new Error()` in domain/application layer
- `grep -rn "throw new Error\|throw new DomainException" src --include="*.ts" | grep -v spec`

---

### 3.3 Add Missing Unit Tests for Untested Services

**Services needing tests (identified from finding.md):**
- `src/application/services/token.service.spec.ts`
- `src/application/services/runtime-identity.service.spec.ts`
- `src/application/services/extensions/extension.executor.spec.ts`
- `src/infrastructure/db/mysql/mysql-token.repository.spec.ts`

**Pattern to follow (from existing spec files):**
- Use `@nestjs/testing` createTestingModule
- Mock dependencies via `get<Service>(Service)`
- Use PBT (fast-check) for complex business logic services

**Verification:**
- `npm run test` should pass
- Test coverage should increase by 5-10%

---

### 3.4 Remove Inline Schemas from Controllers (DTO Migration)

After Phase 2.2 (DTO layer created), remove all inline Zod schemas from:

- `src/interface/http/controllers/auth.controller.ts` — delete lines 61-139
- `src/interface/http/controllers/otp.controller.ts` — delete lines 22-45 (these are already in separate file)
- `src/interface/http/controllers/session.controller.ts` — if any inline schemas
- All other controllers with inline schemas

Replace with:
```typescript
import { SignupEmailInputSchema } from '../../dto/auth/signup-email.input.dto';
// Then: @Body(new ZodValidationPipe(SignupEmailInputSchema))
```

**Verification:**
- No `const.*Schema = z.object` in controller files
- All schemas imported from `src/interface/http/dto/`

---

## Phase 4: Final Verification & Documentation

### 4.1 Verification Checklist

Run all of these before claiming 10/10:

```bash
# Security
grep -rn "helmet\|cors" src/main.ts  # Should have both
grep -rn "console\." src --include="*.ts" | grep -v spec | grep -v .d.ts  # Should be empty

# Architecture
wc -l src/interface/http/controllers/auth.controller.ts  # Should be < 200 lines
ls src/interface/http/controllers/auth/  # Should have 6+ split controllers
ls src/interface/http/dto/auth/  # Should have 10+ DTO files

# Database
grep -rn "function uuidToBuffer\|function bufferToUuid" src/infrastructure/db/mysql  # Should be empty

# Observability
curl http://localhost:3000/health  # Should return JSON

# Testing
npm run test  # All tests pass

# Build
npm run build  # No TypeScript errors
```

### 4.2 Update finding.md with Final Scores

After all phases complete, update `finding.md` with achieved scores and remove the "fix" notes from resolved issues.

---

## Phase Summary

| Phase | Tasks | Deliverables |
|---|---|---|
| **P0** | 3 tasks | Helmet/CORS, no console.log, auth.controller split |
| **P1** | 3 tasks | Health endpoint, DTO layer (10+ files), centralized UUID-Buffer |
| **P2** | 2 tasks | API versioning headers, error→HTTP status mapping |
| **P3** | 2 tasks | Missing unit tests, DTO migration (inline schema removal) |
| **P4** | 2 tasks | Full verification, documentation update |

**Estimated total: 20-25 discrete tasks across 4 phases**
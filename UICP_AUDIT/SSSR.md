# UICP — Unified Identity Control Plane
## Advanced Master Prompt · Multitenant · NestJS + NextJS

---

> ### ⚠ PRIME DIRECTIVES — READ BEFORE TOUCHING A SINGLE FILE
>
> **1. ZERO ASSUMPTIONS.** Never assume a file exists, a module is registered, a column is present, a package is installed, or a pattern is followed. If you have not read it with your own tool call, you do not know it.
>
> **2. ZERO HALLUCINATION.** Never invent file paths, import names, column names, env variable names, or function signatures. Every name you use must come from actual codebase inspection in the current session.
>
> **3. CODEBASE-FIRST ALWAYS.** The mandatory first action in every phase is a structured codebase scan. You must read before you plan. You must plan before you code. You must code before you test.
>
> **4. PHASE GATE.** Each phase has an explicit pass/fail gate. You may not begin the next phase until the current phase gate is green.
>
> **5. ONE CHANGE, ONE VERIFY.** Apply the smallest logical change, then verify it works, before applying the next change.
>
> **6. MULTITENANT EVERYWHERE.** Every data model, every query, every API endpoint, every frontend page must be aware of tenant context. There is no "global" user or resource — everything belongs to a tenant.

---

## Prologue — Project Identity

| Property | Value |
|---|---|
| Product | Unified Identity Control Plane (UICP) |
| Architecture | Multitenant SaaS — shared infrastructure, strict data isolation |
| Backend | NestJS (API) |
| Frontend | NextJS (web app at `@app/web`) |
| Working directory | `C:\Users\HP\Downloads\ccr\UICP` |
| ID strategy | ULID everywhere (replacing UUID) |
| Auth methods | Email+Password, Phone+Password, Email+OTP, Phone+OTP |
| Tenant resolution | Subdomain → header → JWT claim (layered strategy) |

---

## Phase 0 — Codebase Intelligence Gathering (MANDATORY FIRST STEP)

**This phase must complete before any other phase begins. No exceptions.**

### 0.1 — Top-level structure scan

```
Read the root directory tree (2 levels deep).
```

Capture and document:
- Monorepo tool in use: npm workspaces / Turborepo / Nx / Lerna / custom
- Workspace package names and their actual disk paths
- Which package is the NestJS backend (note exact path)
- Which package is the NextJS frontend (note exact path)
- Shared packages, if any (`@uicp/shared`, `@uicp/types`, `@uicp/database`, etc.)
- Root-level config files present: `turbo.json`, `nx.json`, `.npmrc`, `tsconfig.base.json`, `.env`, `.env.example`

### 0.2 — Backend deep scan (NestJS)

Read each of the following and document what you find:

```
package.json         → list all dependencies and devDependencies
tsconfig.json        → strict mode? paths? rootDir? outDir?
src/main.ts          → bootstrap config: port, global prefix, pipes, guards, interceptors
src/app.module.ts    → which modules are imported? any global modules?
src/*/module files   → list every @Module() found
```

Then scan the database layer:
```
If TypeORM:  ormconfig / data-source.ts, all entity files (*.entity.ts), all migration files
If Prisma:   schema.prisma, all migration SQL files in prisma/migrations/
If Knex:     knexfile, all migration files in migrations/
If MikroORM: mikro-orm.config, all entity files
```

Document:
- ORM in use and version
- Database driver (postgres / mysql / sqlite / other)
- Every table/entity that exists today (exact names)
- Every column on every table (exact names, types, nullable, default)
- Every index and foreign key currently defined
- Any seeders/fixtures found (list file names)
- Any existing auth module or JWT strategy found

### 0.3 — Frontend deep scan (NextJS)

Read each of the following:
```
package.json                → next version, tailwind, CSS frameworks, state mgmt, HTTP client
next.config.js / .ts        → rewrites, redirects, env, image domains, output mode
tsconfig.json               → paths, strict, baseUrl
postcss.config.js           → plugins
tailwind.config.ts          → content globs, theme, plugins (if Tailwind used)
src/app/layout.tsx OR
pages/_app.tsx              → how CSS is imported, providers, global state
src/middleware.ts            → what runs on the edge? tenant detection? auth?
.env.local / .env.example   → list every defined variable and its current value/placeholder
```

Document:
- NextJS router type: App Router or Pages Router
- CSS approach: Tailwind / CSS Modules / styled-components / vanilla CSS / other
- How (or if) CSS is imported in the root layout
- Global state management: Zustand / Redux / Jotai / Context / none
- HTTP client: Axios / Fetch / tRPC / React Query / other
- Any hardcoded strings found: URLs, tenant IDs, org names, credentials
- Any existing auth context, session management, or token storage

### 0.4 — Environment variable audit

```
Search every file in the project for: process.env, import.meta.env, NEXT_PUBLIC_, DATABASE_URL, JWT_SECRET, SMTP_, TWILIO_, OTP_
```

Document:
- Every env variable referenced in code (backend and frontend separately)
- Which ones are defined in `.env` files vs. only referenced in code
- Which ones are missing entirely (referenced but never defined)

### 0.5 — Build & dependency audit

```
Read root package.json scripts
Read backend package.json scripts
Read frontend package.json scripts
```

Document:
- Exact command to build the backend
- Exact command to start the backend in production mode
- Exact command to build the frontend
- Exact command to start the frontend in production mode
- Any peer dependency warnings or known resolution conflicts
- Node version required (`.nvmrc`, `engines` field, or `.node-version`)

### 0.6 — Phase 0 Output

Before proceeding, produce a structured summary document:

```
## UICP Codebase Reality Report

### Monorepo
- Tool: [discovered value]
- Backend path: [discovered value]
- Frontend path: [discovered value]
- Shared packages: [list]

### Database
- ORM: [discovered value]
- Tables found: [exhaustive list with column inventory]
- Missing tables: [compare against Phase 4 requirements]
- Missing columns: [compare against Phase 4 requirements]

### Auth
- Existing auth: [what exists today]
- Missing: [what must be built]

### Frontend
- Router: [App Router / Pages Router]
- CSS approach: [discovered value]
- CSS loading status: [working / broken — explain why]
- Hardcoded values found: [exhaustive list with file:line references]

### Environment variables
- Defined: [list]
- Missing: [list — blocks what feature]

### Build
- Backend build command: [exact]
- Frontend build command: [exact]
- Known errors: [list from 0.5]
```

**Phase 0 gate:** This report exists and is complete. ✓

---

## Phase 1 — Bootstrap, Build Failure & Root Cause Analysis - Only Reference

### 1.1 — Attempt initial boot - Only Reference

Using the exact commands discovered in Phase 0:

```bash
cd C:\Users\HP\Downloads\ccr\UICP
npm run build 2>&1 | tee build.log
npm start 2>&1 | tee start.log
```

Capture the **complete** stdout and stderr. Do not summarize or truncate any error line.

### 1.2 — Root Cause Analysis protocol - Only Reference

For every error or warning in `build.log` and `start.log`:

| Field | What to document |
|---|---|
| Error text | Exact message |
| Location | File path + line number |
| Category | One of: `missing-dep`, `env-missing`, `type-error`, `import-error`, `port-conflict`, `module-not-registered`, `orm-config`, `migration-pending`, `circular-dep`, `other` |
| Severity | `build-breaking` / `runtime-crash` / `runtime-warning` |
| Root cause | One sentence explanation based on code read |
| Fix | Specific change required |

Sort the table by severity descending.

### 1.3 — Fix protocol - Only Reference

For each item in the table, in order:
1. Apply the minimal fix.
2. Run `npm run build` (backend only first, then full monorepo).
3. Confirm the specific error is gone.
4. Confirm no new errors appeared.
5. Document: "Fixed: [error text] → [what was changed]"

Do not proceed to fix #N+1 until fix #N is verified green.

### 1.4 — Missing environment variables - Only Reference

For every env variable found missing in Phase 0.4:
- Add it to `.env.example` with a clear comment explaining its purpose and format.
- Add a placeholder to `.env` (or `.env.development`) so the dev build can start.
- Never commit real secrets — use placeholder values like `REPLACE_WITH_YOUR_VALUE`.

### 1.5 — Phase 1 gate - Only Reference

```
npm run build    → exit code 0, zero TypeScript errors
npm start        → server responds on expected port, no unhandled exceptions in first 10 seconds
```

---

## Phase 2 — NestJS Architecture Audit & Module Structure Review - Only Reference

### 2.1 — Module inventory - Only Reference

Read every `*.module.ts` file. For each module, document:
- Module name
- Controllers registered
- Providers registered
- Imports from other modules
- Exports to other modules
- Whether it is global (`@Global()`)

### 2.2 — Multitenant module requirements - Only Reference

A multitenant-correct NestJS architecture for UICP must contain at minimum:

```
TenantModule         — resolves TenantContext from request
AuthModule           — all auth strategies and guards
UsersModule          — user CRUD, profile management
UserPasswordsModule  — password operations (separate from users)
OtpModule            — OTP generation, delivery, verification
TokenModule          — JWT issuance, refresh, revocation
HealthModule         — GET /health for readiness/liveness probes
```

For each missing module: document it as a gap to be created in Phase 4.

### 2.3 — Global pipe, guard, and interceptor audit - Only Reference

Read `src/main.ts`. Confirm or add:

```typescript
// Required global configuration
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,           // strip unknown properties
  forbidNonWhitelisted: true,
  transform: true,           // auto-transform to DTO types
  transformOptions: { enableImplicitConversion: true },
}));

app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));
app.useGlobalFilters(new HttpExceptionFilter());
```

Confirm the global prefix (e.g. `/api/v1`) is set. Document the exact prefix found.

### 2.4 — Phase 2 gate - Only Reference

Module inventory document exists. All required modules are either present or listed as gaps. ✓

---

## Phase 3 — Database Schema Audit, Migration Repair & ULID Migration -Only Reference

### 3.1 — Full schema inventory - Only Reference

Using the ORM discovered in Phase 0.2, read every migration file in chronological order. Build a complete table map:

```
Table: users
  id            type  nullable  default  constraints
  email         ...
  phone         ...
  [every column]
  [every index]
  [every FK]
```

Do this for every table found.

### 3.2 — Required schema for UICP multitenant - Only Reference

Compare your inventory against this canonical schema. Every gap is a new migration to write.

---

#### `tenants`
```
id               char(26)     PK, ULID
name             varchar(255) NOT NULL
slug             varchar(100) NOT NULL, UNIQUE (used for subdomain resolution)
plan             varchar(50)  NOT NULL DEFAULT 'free'
is_active        boolean      NOT NULL DEFAULT true
metadata         jsonb        nullable (custom per-tenant config)
created_at       timestamptz  NOT NULL DEFAULT now()
updated_at       timestamptz  NOT NULL DEFAULT now()

INDEX: slug (for tenant resolution on every request)
```

---

#### `users`
```
id                    char(26)      PK, ULID
tenant_id             char(26)      NOT NULL, FK → tenants.id ON DELETE CASCADE
email                 varchar(320)  nullable
phone                 varchar(20)   nullable
email_verified_at     timestamptz   nullable
phone_verified_at     timestamptz   nullable
otp_code_hash         varchar(255)  nullable  (bcrypt hash of OTP — never store plaintext)
otp_expires_at        timestamptz   nullable
otp_attempts          integer       NOT NULL DEFAULT 0
otp_locked_until      timestamptz   nullable  (lock after N failed attempts)
last_login_at         timestamptz   nullable
last_login_method     varchar(20)   nullable  ('email_password'|'phone_password'|'email_otp'|'phone_otp')
is_active             boolean       NOT NULL DEFAULT true
deleted_at            timestamptz   nullable  (soft delete)
created_at            timestamptz   NOT NULL DEFAULT now()
updated_at            timestamptz   NOT NULL DEFAULT now()

CONSTRAINT: CHECK (email IS NOT NULL OR phone IS NOT NULL)
UNIQUE INDEX: (tenant_id, email) WHERE email IS NOT NULL
UNIQUE INDEX: (tenant_id, phone) WHERE phone IS NOT NULL
INDEX: tenant_id
INDEX: otp_expires_at (for cleanup jobs)
```

---

#### `user_passwords`
```
id               char(26)     PK, ULID
user_id          char(26)     NOT NULL, FK → users.id ON DELETE CASCADE, UNIQUE
tenant_id        char(26)     NOT NULL, FK → tenants.id ON DELETE CASCADE
password_hash    text         NOT NULL  (argon2id hash)
must_reset       boolean      NOT NULL DEFAULT false
last_changed_at  timestamptz  NOT NULL DEFAULT now()
created_at       timestamptz  NOT NULL DEFAULT now()
updated_at       timestamptz  NOT NULL DEFAULT now()

INDEX: user_id
INDEX: tenant_id
```

---

#### `user_profiles`
```
id               char(26)      PK, ULID
user_id          char(26)      NOT NULL, FK → users.id ON DELETE CASCADE, UNIQUE
tenant_id        char(26)      NOT NULL, FK → tenants.id ON DELETE CASCADE
first_name       varchar(100)  NOT NULL
last_name        varchar(100)  NOT NULL
display_name     varchar(200)  nullable
avatar_url       text          nullable
date_of_birth    date          nullable
locale           varchar(10)   NOT NULL DEFAULT 'en'
timezone         varchar(60)   NOT NULL DEFAULT 'UTC'
bio              text          nullable
custom_fields    jsonb         nullable  (tenant-defined extra fields)
created_at       timestamptz   NOT NULL DEFAULT now()
updated_at       timestamptz   NOT NULL DEFAULT now()

INDEX: user_id
INDEX: tenant_id
```

---

#### `roles`
```
id               char(26)     PK, ULID
tenant_id        char(26)     NOT NULL, FK → tenants.id ON DELETE CASCADE
name             varchar(100) NOT NULL
description      text         nullable
is_system        boolean      NOT NULL DEFAULT false  (true = cannot be deleted)
created_at       timestamptz  NOT NULL DEFAULT now()
updated_at       timestamptz  NOT NULL DEFAULT now()

UNIQUE INDEX: (tenant_id, name)
INDEX: tenant_id
```

---

#### `user_roles` (join table)
```
id               char(26)     PK, ULID
user_id          char(26)     NOT NULL, FK → users.id ON DELETE CASCADE
role_id          char(26)     NOT NULL, FK → roles.id ON DELETE CASCADE
tenant_id        char(26)     NOT NULL, FK → tenants.id ON DELETE CASCADE
assigned_at      timestamptz  NOT NULL DEFAULT now()
assigned_by      char(26)     nullable, FK → users.id

UNIQUE INDEX: (user_id, role_id)
INDEX: tenant_id, user_id
```

---

#### `refresh_tokens`
```
id               char(26)     PK, ULID
user_id          char(26)     NOT NULL, FK → users.id ON DELETE CASCADE
tenant_id        char(26)     NOT NULL, FK → tenants.id ON DELETE CASCADE
token_hash       varchar(255) NOT NULL, UNIQUE  (SHA-256 of the raw token)
device_info      jsonb        nullable           (user-agent, IP, device type)
expires_at       timestamptz  NOT NULL
revoked_at       timestamptz  nullable
created_at       timestamptz  NOT NULL DEFAULT now()

INDEX: user_id
INDEX: tenant_id
INDEX: expires_at (for cleanup jobs)
INDEX: token_hash (for lookup on refresh)
```

---

#### `audit_logs`
```
id               char(26)     PK, ULID
tenant_id        char(26)     NOT NULL, FK → tenants.id ON DELETE CASCADE
user_id          char(26)     nullable, FK → users.id ON DELETE SET NULL
action           varchar(100) NOT NULL  (e.g. 'auth.login', 'auth.otp_request', 'user.update')
resource_type    varchar(100) nullable
resource_id      char(26)     nullable
metadata         jsonb        nullable  (IP, user-agent, result, error reason)
created_at       timestamptz  NOT NULL DEFAULT now()

INDEX: tenant_id, created_at
INDEX: user_id, created_at
INDEX: action
```

---

### 3.3 — Migration writing rules - Only Reference

- **Never modify an existing migration file** that has already been applied. Always write a new migration.
- Migration file names must follow the project's existing timestamp format exactly (read existing files to confirm format before creating new ones).
- Each migration must be reversible — `up()` and `down()` must both be correct.
- New migrations must be atomic: one logical change per file (don't bundle 5 table creates into one migration).
- After writing each migration, run it: `migrate:latest` (or ORM equivalent). Fix any errors before writing the next one.

### 3.4 — ULID migration - Only Reference

Install if not already present (check `package.json` first):
```bash
npm install ulid
# For NestJS — confirm @nestjs/typeorm or ORM-specific patterns before applying
```

Replace UUID with ULID at every layer:
- **Migrations**: change `id` columns from `uuid` type / `uuid_generate_v4()` default to `char(26)` / application-generated ULID.
- **Entities/Models**: remove `@PrimaryGeneratedColumn('uuid')` decorators; use `@PrimaryColumn('char', { length: 26 })` with `@BeforeInsert()` generating the ULID.
- **Seeds/Factories**: replace `uuidv4()` or `crypto.randomUUID()` with `ulid()`.
- **FK columns**: change from `uuid` to `char(26)` in all child tables.
- **Sort validation**: confirm all paginated endpoints sort by `created_at` or `id` and that ULID sort order is chronologically correct.

### 3.5 — Phase 3 gate - Only Reference

```
migrate:fresh --seed  → exit code 0, zero errors
All tables exist with all required columns, types, indexes, and FKs
SELECT id FROM users LIMIT 1 → returns a 26-character ULID string, not a UUID
```

---

## Phase 4 — Multitenant Architecture Implementation (NestJS)

### 4.1 — Tenant resolution strategy - Only Reference

Tenants are resolved on every request via a layered strategy. Read `src/main.ts` and any existing middleware before implementing.

**Layer 1 — Subdomain** (primary, for production)
```
Request host: acme.uicp.app → slug = "acme"
Request host: localhost       → use X-Tenant-Slug header fallback
```

**Layer 2 — Header** (for API clients and dev)
```
X-Tenant-Slug: acme
```

**Layer 3 — JWT claim** (already resolved at login time)
```
JWT payload contains tenant_id — used for requests after authentication
```

Implement `TenantMiddleware` in NestJS:
```typescript
// src/tenant/tenant.middleware.ts
// Reads subdomain → header → falls back to null
// Looks up tenant by slug in DB (with in-memory cache, TTL 60s)
// Attaches TenantContext to request object
// Returns 400 if tenant cannot be resolved for routes that require it
```

Implement `TenantContext` interface:
```typescript
interface TenantContext {
  id: string;       // ULID
  slug: string;
  plan: string;
  isActive: boolean;
}
```

Implement `@CurrentTenant()` parameter decorator so any controller can access the resolved tenant without re-querying.

### 4.2 — Tenant isolation in all database queries - Only Reference

**Rule: every query that touches tenant-scoped data must include a `WHERE tenant_id = :tenantId` clause.**

For TypeORM: implement a `TenantBaseEntity` with a discriminator or use query interceptors.
For Prisma: every `findMany`, `findFirst`, `create`, `update`, `delete` call must include `where: { tenant_id: context.tenantId }`.
For Knex: every query builder chain must call `.where('tenant_id', context.tenantId)`.

Verify isolation: after seeding two tenants with users, confirm that a request authenticated as Tenant A cannot retrieve any user belonging to Tenant B.

### 4.3 — Auth flow implementation (NestJS) - Only Reference

Read the existing auth module structure before writing any code. Document what exists, then build what is missing.

---

#### `POST /api/v1/auth/register`

**Request body (DTO with class-validator):**
```typescript
class RegisterDto {
  @IsOptional() @IsEmail()        email?: string;
  @IsOptional() @IsMobilePhone()  phone?: string;
  @ValidateIf(o => !o.phone)      // email required if no phone
  @ValidateIf(o => !o.email)      // phone required if no email

  @IsOptional() @IsString() @MinLength(8) password?: string;
  @IsNotEmpty() @IsString()       firstName: string;
  @IsNotEmpty() @IsString()       lastName: string;
}
```

**Logic:**
1. Resolve tenant from request context (from `TenantMiddleware`).
2. Check uniqueness: `(tenant_id, email)` and/or `(tenant_id, phone)` must not exist.
3. Begin DB transaction.
4. Create `users` row with ULID, tenant_id.
5. Create `user_profiles` row.
6. If password provided: hash with argon2id (`argon2.hash(password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 })`), create `user_passwords` row.
7. Assign default role for tenant.
8. Commit transaction.
9. Issue JWT pair (see Token section).
10. Write audit log: `auth.register`.
11. Return: `{ accessToken, refreshToken, user: { id, email, phone, profile, roles } }`

**Errors:**
- 400 if neither email nor phone provided
- 409 if email/phone already exists for this tenant
- 422 if validation fails

---

#### `POST /api/v1/auth/login`

**Request body:**
```typescript
class LoginDto {
  @IsNotEmpty() @IsString()
  identifier: string;  // email address OR phone number — auto-detected

  @IsEnum(['password', 'otp'])
  method: 'password' | 'otp';

  @IsNotEmpty() @IsString()
  credential: string;  // the password string OR the 6-digit OTP code
}
```

**Logic (all four paths through a single service method):**

```
1. Resolve tenant context.
2. Detect identifier type: is it an email address (contains @) or a phone number?
3. Look up user WHERE tenant_id = ? AND (email = ? OR phone = ?) — use appropriate column.
4. If user not found: return 401 with generic message "Invalid credentials" (do NOT reveal whether identifier exists).
5. If user.is_active = false: return 401 "Account is inactive".

IF method = 'password':
  6. Load user_passwords row for this user.
  7. If no password row exists: return 401 "This account uses OTP login" (generic — do not leak method).
  8. Verify argon2id hash: argon2.verify(storedHash, providedPassword).
  9. If fail: increment failed attempt counter, check lockout. Return 401.

IF method = 'otp':
  6. Check otp_locked_until — if set and in future: return 429 "Too many attempts".
  7. Check otp_code_hash is not null and otp_expires_at is in the future.
  8. If OTP expired: return 401 "OTP has expired. Request a new one."
  9. Verify: argon2.verify(storedOtpHash, providedOtp).
  10. If fail: increment otp_attempts. If >= 5, set otp_locked_until = now + 15min. Return 401.
  11. On success: clear otp_code_hash, otp_expires_at, otp_attempts, otp_locked_until.

10. Update user: last_login_at = now(), last_login_method = detected method string.
11. Issue JWT pair.
12. Write audit log: auth.login with method and identifier type (not the identifier itself).
13. Return: { accessToken, refreshToken, user: { id, email, phone, emailVerifiedAt, phoneVerifiedAt, profile, roles, tenantId } }
```

---

#### `POST /api/v1/auth/otp/request`

**Request body:**
```typescript
class OtpRequestDto {
  @IsNotEmpty() @IsString()
  identifier: string;  // email or phone
}
```

**Logic:**
1. Resolve tenant context.
2. Rate limit check: max 3 OTP requests per (tenant_id, identifier) per 15 minutes. Use in-memory cache or Redis. Return 429 if exceeded.
3. Look up user by identifier in tenant. If not found: return 200 anyway (do not reveal whether account exists).
4. Generate cryptographically secure 6-digit OTP: `crypto.randomInt(100000, 999999).toString()`.
5. Hash OTP with argon2id and store in `users.otp_code_hash`.
6. Set `users.otp_expires_at = now + 10 minutes`.
7. Reset `otp_attempts = 0`, `otp_locked_until = null`.
8. Deliver OTP:
   - If identifier is email → send via configured SMTP/email provider (read config from env: `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_USER`, `SMTP_PASS`).
   - If identifier is phone → send via SMS provider (read from env: `SMS_PROVIDER`, `SMS_API_KEY`, `SMS_FROM`).
9. Write audit log: `auth.otp_request` with delivery channel (do NOT log the OTP itself).
10. Return: `{ message: "If an account with that identifier exists, a code has been sent." }`

**Important:** Never log, return, or expose the plaintext OTP in any response — not even in development mode. Use server-side debug logging with restricted access if needed.

---

#### `POST /api/v1/auth/otp/verify`

Handled inline in `POST /auth/login` when `method = "otp"`. No separate verify endpoint needed — the login endpoint is the verification endpoint.

---

#### `POST /api/v1/auth/token/refresh`

**Request body:**
```typescript
class RefreshTokenDto {
  @IsNotEmpty() @IsString()
  refreshToken: string;
}
```

**Logic:**
1. SHA-256 hash the incoming refresh token.
2. Look up `refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > now()`.
3. If not found: return 401 "Invalid or expired refresh token".
4. Load user and tenant. If user is inactive or tenant is inactive: return 401.
5. Revoke old refresh token: `UPDATE refresh_tokens SET revoked_at = now() WHERE id = ?`.
6. Issue new JWT pair (rotate both tokens).
7. Write audit log: `auth.token_refresh`.
8. Return: `{ accessToken, refreshToken }`

---

#### `POST /api/v1/auth/logout`

**Request body:** `{ refreshToken: string }`
**Auth:** Requires valid access token in Authorization header.

**Logic:**
1. SHA-256 hash the refresh token.
2. Revoke it: `UPDATE refresh_tokens SET revoked_at = now()`.
3. Optionally revoke all tokens for this user if `logoutAll: true` is passed.
4. Write audit log: `auth.logout`.
5. Return: `{ message: "Logged out successfully" }`

---

#### `GET /api/v1/users/me`

**Auth:** Requires `JwtAuthGuard` and `TenantGuard`.

Returns:
```typescript
{
  id: string,
  email: string | null,
  phone: string | null,
  emailVerifiedAt: string | null,
  phoneVerifiedAt: string | null,
  lastLoginAt: string | null,
  lastLoginMethod: string | null,
  isActive: boolean,
  tenantId: string,
  profile: {
    firstName: string,
    lastName: string,
    displayName: string | null,
    avatarUrl: string | null,
    locale: string,
    timezone: string,
    bio: string | null,
    dateOfBirth: string | null,
    customFields: Record<string, unknown> | null,
  },
  roles: Array<{ id: string, name: string }>,
  createdAt: string,
}
```

Never return: `password_hash`, `otp_code_hash`, `otp_expires_at`, `otp_attempts`, `token_hash`.
Use `@Exclude()` decorators on sensitive entity fields or transform manually in the response.

---

#### `PATCH /api/v1/users/me`

**Auth:** Requires `JwtAuthGuard` + `TenantGuard`.

Accepts any subset of profile fields. Email and phone updates require re-verification (set `email_verified_at`/`phone_verified_at` to null on change). Returns the updated `GET /users/me` shape.

---

### 4.4 — JWT token implementation - Only Reference

**Access token payload:**
```json
{
  "sub": "<user_id (ULID)>",
  "tid": "<tenant_id (ULID)>",
  "roles": ["member"],
  "type": "access",
  "iat": 1700000000,
  "exp": 1700003600
}
```

**Refresh token payload:**
```json
{
  "sub": "<user_id (ULID)>",
  "tid": "<tenant_id (ULID)>",
  "jti": "<refresh_token_id (ULID — matches refresh_tokens.id)>",
  "type": "refresh",
  "iat": 1700000000,
  "exp": 1702592000
}
```

**Configuration (read from env — verify env var names in codebase before using):** - Only Reference
```
JWT_ACCESS_SECRET        → signing secret for access tokens (min 64 chars in production)
JWT_REFRESH_SECRET       → separate signing secret for refresh tokens
JWT_ACCESS_EXPIRES_IN    → "1h"
JWT_REFRESH_EXPIRES_IN   → "30d"
```

**Refresh token storage:**
- Raw refresh token: `crypto.randomBytes(48).toString('hex')` (opaque token, 96 hex chars).
- Store SHA-256 hash in `refresh_tokens.token_hash` — never store the raw token in DB.
- Store metadata: user-agent, IP address, device fingerprint in `device_info` JSONB column.

### 4.5 — Guards and decorators - Only Reference

Implement the following (check if any already exist before creating):

```typescript
@Injectable() JwtAuthGuard       // validates access token, attaches user to request
@Injectable() TenantGuard        // confirms request tenant_id matches JWT tenant_id
@Injectable() RolesGuard         // checks user roles against @Roles() decorator

@Decorator() @CurrentUser()      // extracts authenticated user from request
@Decorator() @CurrentTenant()    // extracts resolved tenant from request
@Decorator() @Roles(...roles)    // marks endpoint with required roles
@Decorator() @Public()           // marks endpoint as no-auth-required
```

### 4.6 — Seed updates - Only Reference
Only Reference
Read existing seed files before modifying. Document their structure, then update:

Create seeds in this exact order (dependency order matters):

```
1. Tenants seed
   - Tenant A: { slug: "alpha-corp", name: "Alpha Corp", plan: "pro" }
   - Tenant B: { slug: "beta-labs", name: "Beta Labs", plan: "free" }

2. Roles seed (per tenant)
   - Each tenant gets: "admin", "member", "viewer" (is_system = true)

3. Users seed (per tenant, all with ULID ids)
   - User 1 (Tenant A): email + password auth → create users + user_profiles + user_passwords
   - User 2 (Tenant A): phone + password auth → create users + user_profiles + user_passwords
   - User 3 (Tenant A): email + OTP only → create users + user_profiles (NO user_passwords row)
   - User 4 (Tenant A): phone + OTP only → create users + user_profiles (NO user_passwords row)
   - User 5 (Tenant A): admin user → email + password, assign "admin" role
   - Mirror the same 5 users for Tenant B

4. User roles seed
   - Assign appropriate roles to each seeded user

All passwords must be argon2id hashed with the same cost factors as production.
All IDs must be generated with ulid(), not hardcoded strings.
```

### 4.7 — Phase 4 gate -Only Reference
Only Refrence
```
POST /api/v1/auth/login { identifier: "email@tenantA.com", method: "password", credential: "..." }  → 200
POST /api/v1/auth/login { identifier: "+1234567890",       method: "password", credential: "..." }  → 200
POST /api/v1/auth/otp/request { identifier: "email@tenantA.com" }                                   → 200
POST /api/v1/auth/login { identifier: "email@tenantA.com", method: "otp", credential: "123456" }    → 200
GET  /api/v1/users/me (with Tenant B access token, asking for Tenant A user)                        → 403 or 404
```

---

## Phase 5 — Frontend CSS Diagnosis & Fix (@app/web · NextJS)

### 5.1 — Read before touching

Read the following files completely (discovered in Phase 0.3):
- `next.config.js` or `next.config.ts`
- `postcss.config.js`
- `tailwind.config.ts` (if exists)
- The root layout file (`src/app/layout.tsx` for App Router, `pages/_app.tsx` for Pages Router)
- `package.json` — confirm `next`, `tailwindcss`, `autoprefixer`, `postcss` versions

### 5.2 — CSS diagnostic checklist

Work through every item in order. Document pass/fail for each:

**A — Entry point import**
- App Router: `src/app/layout.tsx` must contain `import './globals.css'` (or the actual filename — read to confirm).
- Pages Router: `pages/_app.tsx` must contain `import '../styles/globals.css'` or equivalent.
- Result: pass if import exists and path resolves to a real file.

**B — CSS file content**
- Read the global CSS file. Confirm it contains either Tailwind directives (`@tailwind base; @tailwind components; @tailwind utilities;`) or actual CSS rules.
- Result: pass if file has content.

**C — PostCSS config**
- Confirm `postcss.config.js` exports `{ plugins: { tailwindcss: {}, autoprefixer: {} } }` (adjust for actual CSS approach).
- Confirm `tailwindcss` and `autoprefixer` packages are in `devDependencies`.

**D — Tailwind content paths**
- Read `tailwind.config.ts`. Confirm `content` array covers all source files where class names are used.
- Example correct value: `['./src/**/*.{js,ts,jsx,tsx,mdx}']`
- Result: fail if content paths are wrong (causes Tailwind to emit no CSS in production).

**E — Next.js CSS constraints**
- CSS Modules (`*.module.css`) can be imported anywhere.
- Global CSS files can ONLY be imported in `_app.tsx` (Pages Router) or the root `layout.tsx` (App Router).
- If a global CSS import exists in a non-root component: this is the bug — move it.

**F — Production build output**
- Run `npm run build` (frontend only).
- Check `.next/static/css/` — confirm `.css` files exist there.
- Check the generated HTML in `.next/server/` — confirm `<link>` tags reference those CSS files.

**G — Asset prefix misconfiguration**
- Check `next.config.js` for `assetPrefix` — if set incorrectly, CSS files load with wrong paths.

### 5.3 — Apply fix

Apply the single root-cause fix found in 5.2. Do not apply speculative fixes. Re-run:
```bash
npm run dev       # Confirm CSS loads in dev
npm run build     # Confirm no CSS errors
npm start         # Confirm CSS loads in production build
```

Verify in browser devtools (Network tab): the `.css` file returns HTTP 200 with `Content-Type: text/css`. Verify in Elements tab: CSS rules from the global stylesheet are applied to the body.

### 5.4 — Phase 5 gate

Dev mode: CSS loads. Production build: CSS loads. Browser devtools: stylesheet applied. Zero FOUC. ✓

---

## Phase 6 — Remove All Hardcoded Values from @app/web

### 6.1 — Discovery scan

Run this search from the `@app/web` root. Document every match with file path and line number:

```bash
# Hardcoded IDs and tenant references
grep -rn --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  -e "tenant" -e "tenantId" -e "tenant_id" \
  src/ app/ pages/ components/ lib/ utils/

# Hardcoded URLs
grep -rn --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  -e "localhost" -e "http://" -e "https://" \
  src/ app/ pages/ components/ lib/ utils/

# Hardcoded credentials or secrets
grep -rn --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  -e "secret" -e "password" -e "apiKey" -e "api_key" \
  src/ app/ pages/ components/ lib/ utils/

# Hardcoded org names or display strings that should be configurable
grep -rn --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  -e "UICP\|Unified Identity\|Control Plane" \
  src/ app/ pages/ components/ lib/ utils/
```

Document every result. Categorize each as: `env-var-needed` / `config-needed` / `remove-entirely`.

### 6.2 — Environment variable schema

Create or update `.env.local` (dev), `.env.production` (prod), and `.env.example` (committed to git):

```env
# ─── API ─────────────────────────────────────────────────────────────────────
# Base URL for all API requests from the browser
NEXT_PUBLIC_API_BASE_URL=https://api.uicp.app

# ─── App identity ────────────────────────────────────────────────────────────
NEXT_PUBLIC_APP_NAME=Unified Identity Control Plane
NEXT_PUBLIC_APP_SHORT_NAME=UICP
NEXT_PUBLIC_SUPPORT_EMAIL=support@uicp.app

# ─── Tenant resolution ───────────────────────────────────────────────────────
# Strategy: 'subdomain' | 'header' | 'path'
NEXT_PUBLIC_TENANT_STRATEGY=subdomain
# Fallback slug for local dev where subdomains are unavailable
NEXT_PUBLIC_DEV_TENANT_SLUG=alpha-corp

# ─── Auth ────────────────────────────────────────────────────────────────────
# Storage key names for tokens (values stored in httpOnly cookies — not localStorage)
NEXT_PUBLIC_ACCESS_TOKEN_KEY=uicp_access
NEXT_PUBLIC_REFRESH_TOKEN_KEY=uicp_refresh

# ─── Feature flags ───────────────────────────────────────────────────────────
NEXT_PUBLIC_ENABLE_PHONE_AUTH=true
NEXT_PUBLIC_ENABLE_OTP_AUTH=true
```

**Rules:**
- `NEXT_PUBLIC_*` variables are exposed to the browser — never put secrets here.
- Tenant ID is resolved server-side (from subdomain or JWT) — never hardcoded in env.
- Access and refresh tokens are stored in httpOnly cookies (set by the backend) — never in localStorage.

### 6.3 — API client setup

Create a centralized API client (if not already present — check first):


### 6.5 — Phase 6 gate

```bash
# This grep must return ZERO results in src/
grep -rn --include="*.ts" --include="*.tsx" \
  -e "localhost" -e "hardcoded-tenant" -e "tenant_id.*=" \
  src/
```

`.env.example` exists, is committed, and documents every variable. `.env`, `.env.local`, `.env.production` are in `.gitignore`. ✓

---

## Phase 7 — Production Hardening

### 7.1 — Backend security checklist

Work through each item. Document pass/fail:

| Item | Check | Fix if failing |
|---|---|---|
| `NODE_ENV=production` | Confirmed set in production start command | Add to prod start script |
| Helmet | `app.use(helmet())` in `main.ts` | Install `helmet`, add to bootstrap |
| CORS | Whitelist from `ALLOWED_ORIGINS` env var | Replace `origin: '*'` with env-based list |
| Rate limiting | `@nestjs/throttler` on all auth endpoints | Install and configure module |
| Argon2id cost | `memoryCost: 65536, timeCost: 3, parallelism: 4` | Update hash config |
| Token secrets | JWT secrets are min 64 chars, env-sourced | Update `.env.example` comments |
| Secure cookies | `Secure`, `HttpOnly`, `SameSite=Strict` on all cookie responses | Update cookie options |
| No debug logs | No `console.log` in auth flow that logs credentials, tokens, or OTPs | Grep and remove |
| Structured logging | Use `pino` or project-standard logger with `level` controlled by env | Implement if missing |
| Graceful shutdown | `app.enableShutdownHooks()` in `main.ts` | Add if missing |
| Health endpoint | `GET /health` returns `{ status: 'ok', timestamp }` | Implement if missing |
| ORM query logging | Disabled in production (performance) | Check ORM config |
| Stack traces | Not exposed in error responses in production | Implement `HttpExceptionFilter` |

### 7.2 — Frontend security checklist

| Item | Check |
|---|---|
| No secrets in `NEXT_PUBLIC_*` vars | Grep confirms no API keys, DB URLs, JWT secrets |
| Tokens in httpOnly cookies | No `localStorage.setItem('token', ...)` in source |
| No `console.log` in production bundle | Next.js `compiler.removeConsole` option enabled in `next.config.js` |
| Content Security Policy | CSP headers set via `next.config.js` headers or middleware |
| No hardcoded values | Phase 6 gate passed |

Add to `next.config.js`:
```javascript
// Remove console statements in production
compiler: {
  removeConsole: process.env.NODE_ENV === 'production' ? { exclude: ['error'] } : false,
},
```

### 7.3 — NestJS production startup verification

```bash
cd C:\Users\HP\Downloads\ccr\UICP
NODE_ENV=production npm run build
NODE_ENV=production npm start
```

Verify:
- Server starts without error within 5 seconds
- `GET /health` returns 200
- `GET /api/v1/auth/login` (no body) returns 400 (validation error, not 500)
- No unhandled promise rejections in logs

### 7.4 — NextJS production startup verification

```bash
cd packages/web  # or wherever @app/web is — use path from Phase 0
npm run build
npm start
```

Verify:
- No TypeScript compilation errors
- No CSS-related errors in build output
- Homepage loads with styles applied
- Network tab shows API_BASE_URL is correct

### 7.5 — End-to-end smoke test matrix

 just a Refrence no implementation on existings system, Execute every test in order. A failure in any row must be fixed before proceeding to the next.

```
AUTH FLOWS
──────────────────────────────────────────────────────────────────────────────
 #   Endpoint                         Input                        Expected
──────────────────────────────────────────────────────────────────────────────
 1   POST /auth/register              email + password             201 + tokens
 2   POST /auth/register              phone only                   201 + tokens
 3   POST /auth/register              email (duplicate same tenant) 409
 4   POST /auth/login                 email + password             200 + tokens + full user
 5   POST /auth/login                 phone + password             200 + tokens + full user
 6   POST /auth/otp/request           email identifier             200 (generic message)
 7   POST /auth/login                 email + otp (correct)        200 + tokens
 8   POST /auth/login                 email + otp (wrong code)     401
 9   POST /auth/login                 email + otp (expired)        401
10   POST /auth/login                 email + otp (5 wrong attempts) 429 lockout
11   POST /auth/otp/request           (4th request in 15min)       429
12   POST /auth/token/refresh         valid refresh token          200 + new tokens
13   POST /auth/token/refresh         revoked refresh token        401
14   POST /auth/logout                valid refresh token          200
15   POST /auth/token/refresh         (after logout)               401

TENANT ISOLATION
──────────────────────────────────────────────────────────────────────────────
16   GET /users/me                    Tenant A token               200 (Tenant A user)
17   GET /users/:id                   Tenant A token + Tenant B user id → 404
18   POST /auth/login                 Tenant A user against Tenant B → 401

USER MANAGEMENT
──────────────────────────────────────────────────────────────────────────────
19   GET /users/me                    valid access token           200 + full profile shape
20   PATCH /users/me                  { firstName: "Updated" }     200 + updated profile
21   GET /users/me                    expired access token         401

SECURITY
──────────────────────────────────────────────────────────────────────────────
22   POST /auth/login                 wrong password               401 (same response time as correct — no timing oracle)
23   GET /api/v1/users/me             no Authorization header      401
24   GET /health                      no auth                      200 { status: "ok" }
25   Any endpoint                     invalid JSON body            400 (not 500)

FRONTEND
──────────────────────────────────────────────────────────────────────────────
26   Open app in browser (dev)        —                            CSS applied, no FOUC
27   Open app in browser (prod build) —                            CSS applied, no FOUC
28   View Network tab                 —                            API calls hit NEXT_PUBLIC_API_BASE_URL
29   View Source / Network tab        —                            No hardcoded tenant IDs or secrets visible
```

### 7.6 — Final build gate

```bash
cd C:\Users\HP\Downloads\ccr\UICP
npm run build && npm start
```

Pass criteria:
- Exit code 0 from build
- Both backend and frontend start successfully
- Zero unhandled exceptions in first 30 seconds of runtime
- Smoke test matrix: all 29 rows green

---

## Appendix A — Global Non-Negotiable Rules

These rules apply in every phase, every file, every decision:

**Codebase-first**
Never assume. Never invent. Read the actual file, then act. If a file path is uncertain, use a directory listing tool before opening it. If a column name is uncertain, read the migration before using it.

**No creative naming**
Use the exact variable names, column names, file names, and module names found in the codebase. Do not rename things for elegance unless renaming is the explicit task.

**Transaction discipline**
Operations that touch multiple tables (register, profile update, role assignment) must use a DB transaction. If the ORM supports it (TypeORM `QueryRunner`, Prisma `$transaction`, Knex `trx`), use it.

**Never log sensitive data**
The following must never appear in any log line: passwords, password hashes, OTP codes, OTP hashes, raw tokens, token hashes, full credit card numbers, full PII fields. Log user IDs, tenant IDs, event names, and sanitized metadata only.

**Migration forward-only**
Never edit a migration that has already been applied. New changes → new migration file.

**Argon2id for passwords and OTPs**
bcrypt is acceptable only if argon2 cannot be installed. Never use MD5, SHA-1, SHA-256 alone, or any fast hash for passwords or OTPs.

**ULID everywhere**
No UUID after Phase 3. All new IDs use `ulid()`. All FK columns are `char(26)`.

**Type safety**
No `any` in TypeScript. No `// @ts-ignore` without a comment explaining why it is unavoidable. NestJS DTOs must use `class-validator` decorators on every field.

**Reversible changes**
Every change must be explainable: "I read [file], I found [problem], I changed [X] to [Y], I verified [test] passes."

---

# API Contract Comprehensive Analysis

**Analysis Date:** 2026-05-16

---

## 1. Controller Inventory

### 1.1 All Controllers

| Controller | File Path | Auth Method | Endpoints |
|------------|-----------|------------|-----------|
| **UnifiedAuthController** | `src/interface/http/controllers/auth/unified-auth.controller.ts` | JWT/API Key/Session | 4 |
| **AuthPasswordController** | `src/interface/http/controllers/auth/auth-password.controller.ts` | JWT | 3 |
| **AuthOAuthController** | `src/interface/http/controllers/auth/auth-oauth.controller.ts` | JWT | 4 |
| **AuthOtpController** | `src/interface/http/controllers/auth/auth-otp.controller.ts` | JWT | 5 |
| **AuthCoreController** | `src/interface/http/controllers/auth/auth-core.controller.ts` | JWT | 3 |
| **UserController** | `src/interface/http/controllers/user.controller.ts` | JWT | 6 |
| **SessionController** | `src/interface/http/controllers/session.controller.ts` | JWT | 4 |
| **RoleController** | `src/interface/http/controllers/governance/role.controller.ts` | JWT | 3 |
| **PolicyController** | `src/interface/http/controllers/governance/policy.controller.ts` | JWT | 4 |
| **PlatformTenantController** | `src/interface/http/controllers/platform/platform-tenant.controller.ts` | Platform API Key | 5 |
| **PlatformSecurityController** | `src/interface/http/controllers/platform/platform-security.controller.ts` | Platform API Key | 4 |
| **PlatformGovernanceController** | `src/interface/http/controllers/platform/platform-governance.controller.ts` | Platform API Key | 3 |
| **ApiKeyController** | `src/interface/http/controllers/api-key.controller.ts` | JWT | 5 |
| **TenantApiKeyController** | `src/interface/http/controllers/tenant-api-key.controller.ts` | JWT | 4 |
| **AppController** | `src/interface/http/controllers/platform/app.controller.ts` | JWT | 4 |
| **WebhookController** | `src/interface/http/controllers/platform/webhook.controller.ts` | JWT | 3 |
| **HealthController** | `src/interface/http/controllers/health.controller.ts` | None | 1 |

---

## 2. Endpoint Analysis

### 2.1 Authentication Endpoints

**POST /v1/auth/attempt**
- **Purpose:** Single entry point for authentication
- **Request:**
  ```typescript
  {
    identity: string;        // max 320 chars
    authMethod: 'password' | 'otp' | 'magic_link' | 'oauth';
    secret?: string;
    stateToken?: string;
    deviceFingerprint?: string;
    userAgent?: string;
  }
  ```
- **Response:**
  ```typescript
  {
    data: {
      state: 'authenticated' | 'identity_not_found' | 'profile_required';
      accessToken?: string;
      refreshToken?: string;
      sessionId?: string;
    }
  }
  ```
- **Validation:** Zod schema
- **Security:** Rate limiting NOT implemented

**POST /v1/auth/profile/complete**
- **Purpose:** Complete user profile after auto-create
- **Request:** `{ stateToken: string, profileData: record<string> }`

**POST /v1/auth/refresh**
- **Purpose:** Refresh access token
- **Security:** Family-based rotation, replay detection

**POST /v1/auth/logout**
- **Purpose:** Invalidate session

### 2.2 User Endpoints

**GET /v1/users/me** - Get current user profile
**PATCH /v1/users/me** - Update user profile
**DELETE /v1/users/me** - Soft delete user

### 2.3 Session Endpoints

**GET /v1/sessions** - List user sessions
**DELETE /v1/sessions/:sessionId** - Revoke specific session
**DELETE /v1/sessions** - Revoke all sessions

### 2.4 Governance Endpoints

**GET/POST /v1/roles** - List/create roles
**POST /v1/roles/assign** - Assign role to user
**GET/POST /v1/policies** - List/create ABAC policies

---

## 3. Validation Patterns

### 3.1 Zod Usage

Most controllers use Zod for validation:

```typescript
const attemptDto = z.object({
  identity: z.string().min(1).max(320),
  authMethod: z.enum(['password', 'otp', 'magic_link', 'oauth']).default('password'),
  secret: z.string().max(128).optional(),
  stateToken: z.string().optional(),
  deviceFingerprint: z.string().max(64).optional(),
  userAgent: z.string().optional(),
});
```

Validation pipe: `ZodValidationPipe`

---

## 4. Authentication Patterns

### 4.1 Multi-Method Auth Guard

The JwtAuthGuard supports:

1. **JWT (Bearer token)** - RS256 signed
2. **API Keys (uF/pB/sF/tB prefix)** - ULID-based format with HMAC
3. **Internal Service** - X-Internal-Service-Token header
4. **Session Token** - X-Session-Token header

### 4.2 Tenant Resolution

- Primary: `x-tenant-id` header
- Fallback: JWT claim `tid`

---

## 5. Error Response Patterns

### 5.1 Consistent Format

```typescript
{
  error: {
    code: string;
    message: string;
    details?: any;
  }
}
```

### 5.2 HTTP Status Codes

| Status | Usage |
|--------|-------|
| 200 | Success |
| 201 | Created |
| 400 | Validation Error |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 500 | Internal Error |

---

## 6. API Key Format (v1)

| Prefix | Purpose |
|--------|---------|
| uF | User publishable |
| pB | Platform backend |
| sF | Service |
| tB | Tenant |

Structure: `{type}{ulid}` - 2 character prefix + 26 character ULID

---

## 7. Rate Limiting Gaps

| Endpoint Type | Limit | Window |
|---------------|-------|--------|
| API Key | 1000 | 60 seconds |
| JWT Auth | NOT IMPLEMENTED | - |
| Auth Endpoint | NOT IMPLEMENTED | - |

---

## 8. Security Concerns

| Issue | Severity | Location |
|-------|----------|----------|
| No rate limiting on auth endpoints | HIGH | UnifiedAuthController |
| Manual JSON parsing of state token | MEDIUM | unified-auth.controller.ts:114 |
| Direct cache access in controller | HIGH | session.controller.ts:119 |
| Type casting abuse | MEDIUM | user.controller.ts |

---

## 9. Consistency Assessment

### Good Patterns
- Consistent error response format
- Consistent authentication via JwtAuthGuard
- Consistent tenant resolution
- Zod validation on most endpoints

### Inconsistencies
- Some controllers use class-validator, others use Zod
- Some endpoints missing OpenAPI annotations
- Different response shapes for similar operations

---

## 10. Conclusion

The API layer demonstrates **good overall design** with:
- Clean RESTful patterns
- Consistent authentication
- Strong validation via Zod
- Proper error handling

**Primary Concerns:**
1. Missing rate limiting on critical endpoints
2. Some encapsulation violations (direct cache access)
3. Inconsistent validation patterns (Zod vs class-validator)
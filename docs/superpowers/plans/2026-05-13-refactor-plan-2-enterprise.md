# UICP Enterprise Refactoring Plan: Phase 1-4

> **Updated Focus:** Faster API responses, Enterprise-grade features, NPM TS-only SDK

---

## PHASE 1: P0 Security Hardening (Critical Path)

### 1.1 ABAC AST Interpreter
- **Files:** 
  - `src/domain/policy/interpreter/abac-ast-interpreter.ts` (CREATE)
  - `src/domain/policy/parser/abac-policy-parser.ts` (CREATE)
  - Delete: `src/infrastructure/governance/policy/abac-jit-compiler.ts`
- **Goal:** Eliminate RCE vulnerability

### 1.2 Atomic Rate Limiting (Lua)
- **Files:**
  - `src/infrastructure/rate-limit/sliding-window.lua` (CREATE)
  - `src/infrastructure/rate-limit/atomic-rate-limiter.service.ts` (CREATE)
- **Goal:** Fix race condition causing permanent DoS

### 1.3 OTP Cost Controller
- **Files:**
  - `src/application/services/otp/otp-cost-controller.service.ts` (CREATE)
  - `src/infrastructure/otp/gateway-composite.service.ts` (CREATE)
- **Goal:** Prevent SMS cost explosion

---

## PHASE 2: API Performance Optimization (Faster Responses)

### 2.1 Response Caching Layer
- **Files:**
  - `src/interface/http/interceptors/cache.interceptor.ts` (CREATE)
  - `src/application/services/cache/response-cache.service.ts` (CREATE)
- **Strategy:** Redis-based response caching with TTL
- **Cache Keys:** `cache:{tenant}:{method}:{hash(params)}`

### 2.2 Database Query Optimization
- **Files:**
  - Optimize: `src/infrastructure/db/mysql/mysql-user.repository.ts`
  - Optimize: `src/infrastructure/db/mysql/mysql-identity.repository.ts`
- **Strategy:** Add covering indexes, N+1 query elimination via JOINs

### 2.3 Connection Pool Tuning
- **Files:**
  - `src/infrastructure/db/mysql/database.module.ts` (MODIFY)
- **Strategy:** Tune MySQL pool size, add read replica routing for GET requests

### 2.4 Payload Compression
- **Files:**
  - `src/main.ts` (MODIFY) - enable gzip/brotli compression
- **Strategy:** Compress responses > 1KB

---

## PHASE 3: Enterprise Features

### 3.1 Multi-Tenant Advanced Governance
- **Files:**
  - `src/application/services/tenant/tenant-quota.service.ts` (CREATE)
  - `src/application/services/tenant/tenant-analytics.service.ts` (CREATE)
- **Features:**
  - Per-tenant API quota tracking
  - Spend limits per feature (SMS, storage, API calls)
  - Tenant health dashboard data

### 3.2 Advanced Audit & Compliance
- **Files:**
  - `src/application/services/audit/audit-export.service.ts` (CREATE)
  - `src/infrastructure/audit/compliance-reporter.service.ts` (CREATE)
- **Features:**
  - SOC2-compatible audit logs
  - GDPR data export
  - Retention policies

### 3.3 Enterprise Identity Features
- **Files:**
  - `src/domain/identity/services/saml-sso.service.ts` (CREATE)
  - `src/domain/identity/services/oidc-provider.service.ts` (CREATE)
- **Features:**
  - SAML 2.0 SSO support
  - OIDC provider capability

### 3.4 Role-Based Access Control (RBAC) Enhancement
- **Files:**
  - `src/application/services/rbac/role-hierarchy.service.ts` (CREATE)
  - `src/application/services/rbac/permission-matrix.service.ts` (CREATE)
- **Features:**
  - Role hierarchy (admin > manager > user)
  - Permission matrix with resource-level grants

---

## PHASE 4: TypeScript SDK (NPM Only)

### 4.1 SDK Package Structure
- **Location:** `packages/sdk/`
- **Output:** `@uicp/sdk` on npm

### 4.2 Implementation (Per Spec)
| Component | File |
|-----------|------|
| Types | `packages/sdk/src/types.ts` |
| Errors | `packages/sdk/src/errors.ts` |
| Token Vault | `packages/sdk/src/token-vault.ts` |
| Event Bus | `packages/sdk/src/event-bus.ts` |
| Storage Adapters | `packages/sdk/src/storage/*.ts` |
| HTTP Layer | `packages/sdk/src/http/pipeline.ts` |
| Interceptors | `packages/sdk/src/http/interceptors/*.ts` |
| Module Clients | `packages/sdk/src/modules/*.ts` |
| Main Client | `packages/sdk/src/client.ts` |

### 4.3 Features (Per Spec)
- Auto token refresh
- Auto token clear on logout/changePassword/deleteMe
- Auto idempotency keys on cost-critical endpoints
- Missing APIs throw `UICPNotImplementedError`

---

## Implementation Order

```
Phase 1 (Week 1-2): P0 Security
  ├── 1.1 ABAC AST Interpreter
  ├── 1.2 Lua Rate Limiter
  └── 1.3 OTP Cost Controller

Phase 2 (Week 2-3): Performance
  ├── 2.1 Response Caching
  ├── 2.2 DB Query Optimization
  ├── 2.3 Connection Pool
  └── 2.4 Payload Compression

Phase 3 (Week 3-4): Enterprise
  ├── 3.1 Multi-Tenant Governance
  ├── 3.2 Audit & Compliance
  ├── 3.3 Enterprise Identity
  └── 3.4 RBAC Enhancement

Phase 4 (Week 4-5): SDK
  └── Full SDK implementation per spec
```

---

## Success Metrics

| Metric | Target |
|--------|--------|
| API Response P50 | < 50ms |
| API Response P99 | < 200ms |
| Security Vulnerabilities | 0 Critical/High |
| SDK Bundle Size | < 50KB gzipped |
| Test Coverage | > 80% |
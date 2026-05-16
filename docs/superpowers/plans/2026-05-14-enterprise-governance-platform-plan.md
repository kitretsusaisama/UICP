# Enterprise Governance Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement an enterprise-grade governance platform with W3C DID identity, Azure PIM-style JIT access, AI predictive security, Zero Trust architecture, and multi-region active-active deployment.

**Architecture:** 10-phase implementation starting with Platform Identity foundation (Phase 1), then building up through DID/VC identity, RBAC+ABAC authorization, Zero Trust, Conditional Access, Azure PIM JIT, AI Security, Self-Healing, Data Governance, and Multi-Region support. Each phase produces working, testable software.

**Tech Stack:** TypeScript, NestJS, MySQL, Redis

---

## PHASE 1: Foundation (Platform Identity & RBAC)

### Task 1: Platform Identity Entity

**Files:**
- Create: `src/domain/entities/platform-identity.entity.ts`
- Create: `src/domain/value-objects/platform-identity-id.vo.ts`
- Test: `src/domain/entities/platform-identity.entity.spec.ts`

**Requirements:**
- PlatformIdentityId value object (ULID-based)
- PlatformIdentity entity with email, displayName, passwordHash
- MFA support (totp, webauthn, email, none)
- Risk score (0.0-1.0) and risk level (low, medium, high, critical)
- Status management (active, suspended, deactivated, pending)
- Last login tracking (timestamp, IP, device)
- Methods: verifyPassword, updatePassword, enableMFA, disableMFA, recordLogin, updateRiskScore, suspend, reactivate, deactivate

**Tests:**
- create() sets pending status
- suspend/reactivate workflow
- MFA enable/disable
- Risk score updates

---

### Task 2: Platform Role Entity

**Files:**
- Create: `src/domain/entities/platform-role.entity.ts`
- Create: `src/domain/repositories/platform-role.repository.interface.ts`
- Test: `src/domain/entities/platform-role.entity.spec.ts`

**Requirements:**
- System-defined roles: PLATFORM_OWNER, PLATFORM_ADMIN, SUPPORT_TIER1, SUPPORT_TIER2, AUDITOR, SECURITY_ADMIN, NETWORK_ADMIN, BILLING_ADMIN
- Role types: permanent, eligible (JIT), delegated
- Permission management (add, remove, check)
- Inheritance levels for role hierarchy

**Tests:**
- hasPermission with exact match and wildcard
- requiresJITActivation for eligible roles
- addPermission/removePermission

---

### Task 3: Platform Identity Repository & MySQL Implementation

**Files:**
- Create: `migrations/V033__platform_identities.sql`
- Create: `src/domain/repositories/platform-identity.repository.interface.ts`
- Create: `src/infrastructure/db/mysql/mysql-platform-identity.repository.ts`
- Test: `src/infrastructure/db/mysql/mysql-platform-identity.repository.spec.ts`

**Requirements:**
- platform_identities table (id, email, display_name, password_hash, mfa_type, mfa_secret, mfa_enabled, risk_score, risk_level, status, last_login_at, last_login_ip, last_login_device)
- platform_identity_roles table (identity_id, role_id, assignment_type, assigned_by, assigned_at, activated_at, expires_at, justification)
- CRUD operations for identities
- Role assignment management

**Tests:**
- save identity to database
- findById returns null for non-existent
- findByEmail lookup
- assignRole operation

---

### Task 4: Platform Identity Service

**Files:**
- Create: `src/application/services/platform-identity.service.ts`
- Test: `src/application/services/platform-identity.service.spec.ts`

**Requirements:**
- create() with conflict check
- findById/findByEmail
- listAll with pagination
- assignRole/removeRole with type (permanent/eligible)
- suspend/reactivate with reason
- updatePassword with secure hashing
- enableMFA
- recordLogin with IP and device
- updateRiskScore with automatic level calculation

**Tests:**
- create() throws ConflictException if email exists
- assignRole sets eligible type for eligible roles
- suspend updates risk level
- updateRiskScore sets correct level based on score thresholds

---

### Task 5: Platform Auth Controller & Guard

**Files:**
- Create: `src/interface/http/controllers/platform/identity.controller.ts`
- Create: `src/interface/http/guards/platform-auth.guard.ts`
- Create: `src/interface/http/dto/platform/create-identity.dto.ts`
- Create: `src/interface/http/dto/platform/assign-role.dto.ts`
- Test: `src/interface/http/controllers/platform/identity.controller.spec.ts`

**Requirements:**
- POST /platform/v1/identities - Create identity
- GET /platform/v1/identities - List all
- GET /platform/v1/identities/:id - Get by ID
- POST /platform/v1/identities/:id/roles - Assign role
- DELETE /platform/v1/identities/:id/roles/:roleId - Remove role
- POST /platform/v1/identities/:id/suspend - Suspend
- POST /platform/v1/identities/:id/reactivate - Reactivate
- POST /platform/v1/identities/:id/password - Reset password

**Auth Guard:**
- Verify Bearer token
- Check identity is active
- Check MFA if enabled
- Block critical risk level
- RequirePlatformRoles decorator for RBAC

**Tests:**
- create returns success with identity data
- list returns all identities with total
- assignRole calls service with correct parameters

---

### Task 6: Impersonation Service (Customer Lockbox)

**Files:**
- Create: `src/domain/entities/impersonation-session.entity.ts`
- Create: `migrations/V037__platform_impersonation_sessions.sql`
- Create: `src/application/services/impersonation.service.ts`
- Create: `src/interface/http/controllers/platform/impersonation.controller.ts`
- Test: `src/application/services/impersonation.service.spec.ts`

**Requirements:**
- ImpersonationSession entity with 4-hour auto-timeout
- Fields: id, platformIdentityId, tenantId, targetIdentityId, reason, startedAt, endedAt, expiresAt, ipAddress, userAgent, actionsLog, requiresApproval, approvedBy, approvedAt, status
- Methods: logAction, end, cancel, expire, isExpired, isActive, toDTO, toAuditReport
- ImpersonationService with start(), approve(), end(), logAction(), getActiveSession(), getAuditReport()
- ImpersonationController with start, end, list, approve endpoints

**Endpoints:**
- POST /platform/v1/impersonate/start - Start session
- POST /platform/v1/impersonate/end - End session
- GET /platform/v1/impersonate/sessions - List active
- GET /platform/v1/impersonate/sessions/:id/audit - Get audit report
- POST /platform/v1/impersonate/sessions/:id/approve - Approve

**Tests:**
- start() rejects if no impersonation permission
- start() rejects if active session exists
- end() ends active session
- logAction() logs to active session

---

### Task 7: Approval Workflow Service

**Files:**
- Create: `src/domain/entities/approval-request.entity.ts`
- Create: `migrations/V038__platform_approval_requests.sql`
- Create: `src/application/services/approval-workflow.service.ts`
- Create: `src/interface/http/controllers/platform/approval.controller.ts`
- Test: `src/application/services/approval-workflow.service.spec.ts`

**Requirements:**
- ApprovalRequest entity with multi-step approval
- CRITICAL_ACTIONS: tenant.delete (2 approvers), identity.delete (2), platform_owner.grant (2), global_config.modify (1), admin.force_reset (1), tenant.access_all_data (2)
- ApprovalSteps with approver tracking
- Expiry based on urgency (critical: 1h, high: 4h, normal: 24h, low: 72h)
- ApprovalWorkflowService with create(), approve(), reject(), listPending(), listByRequester()
- ApprovalController with request, list, approve, reject endpoints

**Endpoints:**
- POST /platform/v1/approvals/request - Create request
- GET /platform/v1/approvals - List pending
- GET /platform/v1/approvals/my - My requests
- GET /platform/v1/approvals/:id - Get by ID
- POST /platform/v1/approvals/:id/approve - Approve step
- POST /platform/v1/approvals/:id/reject - Reject step

**Tests:**
- create() sets correct number of approvers per action type
- approve() processes step
- reject() immediately rejects request
- throws if request not found or already decided

---

## Implementation Order

Execute tasks in order. Each task must pass:
1. Implementation + unit tests
2. Spec compliance review
3. Code quality review

Then move to next task. Do not skip reviews.
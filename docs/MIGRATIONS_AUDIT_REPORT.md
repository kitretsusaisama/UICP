---
name: uicp-migrations-audit-report
description: UICP Migrations Audit Report - Database Schema Analysis
metadata:
  type: reference
  project: UICP
  date: 2026-05-12
---

# UICP Database Migrations Audit & Refactor Report

**Project:** Universal Identity & Communication Platform
**Audit Date:** 2026-05-12
**Auditor:** Claude Code Design System

---

## 1. FIRST MIGRATIONS AUDIT & REFACTOR

### 1.1 Password Tracking Assessment

**STATUS: ✅ FOUND**

Passwords are stored across TWO architectural layers:

| Table | Architecture Layer | Linked To | Purpose |
|-------|-------------------|-----------|---------|
| `credentials` | User Aggregate (V005) | `user_id` → `users` | Legacy user-based auth |
| `principal_credentials` | Principal System (V020) | `principal_id` → `global_principals` | Modern principal-based auth |

**Correction:** These are NOT duplicates — they serve **different architectural layers**:
- `credentials` — User aggregate (V003-based system)
- `principal_credentials` — Global principals (V018-based system with `tenant_memberships`)

Both use `bcrypt_v1` or `argon2id_v1` algorithms with configurable rounds.

---

### 1.2 Data Tracking Audit (What We Track)

#### ✅ Comprehensive Tracking Found:

| Category | Data Tracked | Tables |
|----------|-------------|--------|
| **User Identity** | Email, phone, OAuth providers | `identities`, `principal_auth_methods` |
| **Auth Events** | Login, OTP, MFA verification | `sessions`, `otp_attempts`, `otp_flows` |
| **Session Metadata** | IP hash, User-Agent, device fingerprint | `sessions`, `otp_delivery_telemetry` |
| **Audit Logs** | Actor, action, resource, IP, checksums | `audit_logs`, `otp_isolation_audit` |
| **SOC Alerts** | Threat score, kill chain stage, signals | `soc_alerts` |
| **Domain Events** | Full event sourcing | `domain_events`, `outbox_events` |
| **Communication** | Email/SMS delivery status, latency | `email_logs`, `communication_delivery_attempts` |
| **Provider Health** | Circuit breaker state, success rates | `provider_health`, `email_provider_health` |
| **Tenant Isolation** | Tenant-specific configs, risk policies | `tenant_otp_widget_configs`, `tenant_otp_risk_policies` |
| **OTP Telemetry** | Channel success rates, provider performance | `otp_delivery_telemetry` |

---

### 1.3 Missing Data Tracking (Gaps Found)

#### ❌ NOT Tracked But Should Be:

| Gap | Impact | Table to Add |
|-----|--------|--------------|
| **User login timestamp** | No last_login_at on users | `users` table |
| **Failed login attempts count** | Brute force detection | `users` table |
| **Password change history** | Rotation enforcement | `password_history` table |
| **Identity verification method** | Audit of HOW verified | `identity_verification_audit` |
| **Device first-seen timestamp** | Trust timeline | `devices` table |
| **Session login method** | Auth analysis | `sessions` table |
| **Session geo-location** | Risk scoring | `sessions` table |
| **OTP verification metadata** | Delivery intelligence | `otp_flows` table |
| **User activity summary** | Analytics | `user_activity_summary` |

---

### 1.4 Recommended Refactor Migration (V029)

**File:** `migrations/V029__enhance_user_tracking.sql`

```sql
-- ============================================================================
-- ENHANCE USERS TABLE - Add login/password tracking fields
-- ============================================================================
ALTER TABLE users
ADD COLUMN last_login_at DATETIME(3) AFTER updated_at,
ADD COLUMN login_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER last_login_at,
ADD COLUMN failed_login_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER login_count,
ADD COLUMN last_failed_login_at DATETIME(3) AFTER failed_login_count,
ADD COLUMN password_changed_at DATETIME(3) AFTER last_failed_login_at,
ADD COLUMN password_change_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER password_changed_at,
ADD COLUMN last_identity_verified_at DATETIME(3) AFTER password_change_count,
ADD COLUMN last_login_ip_hash BINARY(32) AFTER last_identity_verified_at,
ADD COLUMN total_session_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER last_login_ip_hash,
ADD COLUMN active_session_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER total_session_count;

CREATE INDEX idx_users_last_login ON users (tenant_id, last_login_at);
CREATE INDEX idx_users_failed_logins ON users (tenant_id, failed_login_count);

-- ============================================================================
-- ENHANCE SESSIONS TABLE - Add login method and geo tracking
-- ============================================================================
ALTER TABLE sessions
ADD COLUMN login_method ENUM('password','sso','oauth','magic_link','otp') NOT NULL DEFAULT 'password' AFTER created_at,
ADD COLUMN mfa_method ENUM('totp','sms','email','webauthn','passkey','none') DEFAULT 'none' AFTER login_method,
ADD COLUMN initial_ip_hash BINARY(32) AFTER mfa_method,
ADD COLUMN geo_country VARCHAR(2) AFTER initial_ip_hash,
ADD COLUMN geo_city VARCHAR(128) AFTER geo_country,
ADD COLUMN trust_level ENUM('trusted','untrusted','new_device','risk_verified') DEFAULT 'new_device' AFTER geo_city,
ADD COLUMN auth_factors JSON AFTER trust_level;

CREATE INDEX idx_sessions_geo ON sessions (tenant_id, geo_country, created_at);
CREATE INDEX idx_sessions_trust ON sessions (tenant_id, trust_level, created_at);

-- ============================================================================
-- USER LOGIN HISTORY - Forensic logging for security analysis
-- ============================================================================
CREATE TABLE user_login_history (
  id                      BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  login_method            ENUM('password','sso','oauth','magic_link','otp') NOT NULL,
  success                 TINYINT(1)    NOT NULL,
  failure_reason          VARCHAR(128),
  ip_hash                 BINARY(32)    NOT NULL,
  geo_country             VARCHAR(2),
  geo_city                VARCHAR(128),
  user_agent              VARCHAR(512),
  device_id               BINARY(16),
  mfa_used                TINYINT(1)    NOT NULL DEFAULT 0,
  mfa_method              VARCHAR(32),
  session_id              BINARY(16),
  provider_name           VARCHAR(64),
  created_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (id),
  INDEX idx_user_time (user_id, created_at DESC),
  INDEX idx_tenant_time (tenant_id, created_at DESC),
  INDEX idx_tenant_user (tenant_id, user_id, created_at DESC),
  INDEX idx_ip (tenant_id, ip_hash, created_at DESC),
  INDEX idx_success (tenant_id, success, created_at DESC),
  INDEX idx_geo (tenant_id, geo_country, created_at DESC),
  INDEX idx_login_method (tenant_id, login_method, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
PARTITION BY RANGE (TO_DAYS(created_at)) (
  PARTITION p_default VALUES LESS THAN MAXVALUE
);

-- ============================================================================
-- PASSWORD HISTORY - Track last 5 password hashes for rotation enforcement
-- ============================================================================
CREATE TABLE password_history (
  id                      BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  hash                    VARCHAR(255)  NOT NULL,
  algorithm               VARCHAR(32)   NOT NULL,
  rounds                  TINYINT UNSIGNED,
  pwned                   TINYINT(1)    NOT NULL DEFAULT 0,
  created_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (id),
  INDEX idx_user_created (user_id, created_at DESC),
  INDEX idx_user_recent (user_id, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- IDENTITY VERIFICATION AUDIT - Track how identities are verified
-- ============================================================================
CREATE TABLE identity_verification_audit (
  id                      BINARY(16)    NOT NULL,
  identity_id             BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  verification_method     ENUM('email_link','sms_otp','email_otp','manual','oauth','admin','api','webauthn') NOT NULL,
  verified_by             BINARY(16),
  ip_hash                 BINARY(32),
  geo_country             VARCHAR(2),
  user_agent              VARCHAR(512),
  created_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (id),
  INDEX idx_identity (identity_id, created_at DESC),
  INDEX idx_user (user_id, created_at DESC),
  INDEX idx_tenant_time (tenant_id, created_at DESC),
  INDEX idx_method (tenant_id, verification_method, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- ENHANCE DEVICES TABLE - Add first-seen and login tracking
-- ============================================================================
ALTER TABLE devices
ADD COLUMN first_seen_at DATETIME(3) NOT NULL AFTER last_seen_at,
ADD COLUMN login_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER first_seen_at,
ADD COLUMN last_login_at DATETIME(3) AFTER login_count,
ADD COLUMN model VARCHAR(64) AFTER last_login_at,
ADD COLUMN os_name VARCHAR(64) AFTER model,
ADD COLUMN os_version VARCHAR(32) AFTER os_name,
ADD COLUMN app_name VARCHAR(64) AFTER os_version,
ADD COLUMN app_version VARCHAR(32) AFTER app_name,
ADD COLUMN last_ip_hash BINARY(32) AFTER app_version,
ADD COLUMN last_geo_country VARCHAR(2) AFTER last_ip_hash;

-- Backfill first_seen_at for existing devices
UPDATE devices SET first_seen_at = created_at WHERE first_seen_at IS NULL;

-- ============================================================================
-- CREDENTIAL CHANGE AUDIT - Track credential changes for security
-- ============================================================================
CREATE TABLE credential_change_audit (
  id                      BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  change_type             ENUM('password_set','password_change','password_reset','credential_added','credential_removed') NOT NULL,
  algorithm               VARCHAR(32),
  rounds                  TINYINT UNSIGNED,
  changed_by              BINARY(16),
  ip_hash                 BINARY(32),
  user_agent              VARCHAR(512),
  session_id              BINARY(16),
  reason                  VARCHAR(255),
  created_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (id),
  INDEX idx_user_time (user_id, created_at DESC),
  INDEX idx_tenant_time (tenant_id, created_at DESC),
  INDEX idx_change_type (tenant_id, change_type, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- USER ACTIVITY SUMMARY - Aggregated analytics table
-- ============================================================================
CREATE TABLE user_activity_summary (
  user_id                 BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  date_key                DATE          NOT NULL,
  login_count             INT UNSIGNED  NOT NULL DEFAULT 0,
  failed_login_count      INT UNSIGNED  NOT NULL DEFAULT 0,
  active_minutes          INT UNSIGNED  NOT NULL DEFAULT 0,
  mfa_count               INT UNSIGNED  NOT NULL DEFAULT 0,
  ip_addresses_used       INT UNSIGNED  NOT NULL DEFAULT 0,
  devices_used            INT UNSIGNED  NOT NULL DEFAULT 0,
  last_activity_at        DATETIME(3),
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (user_id, date_key),
  INDEX idx_tenant_date (tenant_id, date_key),
  INDEX idx_active_users (tenant_id, login_count, date_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert schema version
INSERT INTO schema_versions (version, description, checksum, applied_at, applied_by, duration_ms)
VALUES (29, 'Add comprehensive user tracking, login history, and audit fields', SHA2('V029__enhance_user_tracking', 256), NOW(3), 'system', 0);
```

---

## 2. META ENGINEER V030 - ADVANCED TELEMETRY

### 2.1 What's New in V030

**Created 6 New Tables:**

| Table | Purpose | Meta Engineer Value |
|-------|---------|---------------------|
| `security_events` | Granular security event logging | Threat detection, SIEM integration |
| `api_metrics` | End-to-end API performance | P99 latency tracking, optimization |
| `tenant_metrics` | Per-tenant usage analytics | Billing, health scoring, capacity planning |
| `rate_limit_events` | Throttling telemetry | Abuse prevention, DoS detection |
| `threat_intelligence` | IOC correlation & tracking | Credential stuffing, brute force patterns |
| `user_behavior_events` | Product funnel analytics | Conversion optimization, engagement |

**Enhanced 7 Existing Tables:**

| Table | New Columns | Value |
|-------|-------------|-------|
| `sessions` | ip_change_count, geo_anomaly_score, last_activity_at, activity_count, avg_action_latency_ms | Session hijack detection |
| `audit_logs` | user_id, principal_id, correlation_id, request/response metadata | Full request traceability |
| `soc_alerts` | attack_type, ioc tracking, ml_model confidence | Richer threat context |
| `otp_attempts` | delivery_latency_ms, attempt_number, provider_response | OTP delivery intelligence |
| `global_principals` | risk_score, identity_verified, login_streak_days | Principal risk profiling |
| `tenants` | active_users_count, total_api_calls, health_score, subscription_status | Tenant lifecycle mgmt |
| `devices` | trust_score, is_rooted, is_emulator, screen_lock_enabled | Device security posture |

### 2.2 V030 Security Telemetry Details

```sql
-- 30+ event types tracked for security:
- login_success, login_failed, login_blocked
- credential_stuffed, brute_force_attempt
- anomalous_ip, anomalous_geo, session_hijack_suspected
- token_reused, jwt_invalid, refresh_token_rotated
- impersonation_detected, privilege_escalation
```

### 2.3 V030 Performance Metrics

```sql
-- Every API call tracked with:
- latency_ms (total, db_query_time, external_api_time)
- cache_hit boolean
- db_query_count
- path_template (normalized for aggregation)
- correlation_id for request tracing
- error_type, error_message for debugging
```

### 2.4 V030 Tenant Intelligence

```sql
-- Daily aggregated metrics per tenant:
- active_users, new_users, deleted_users
- total_logins, failed_logins, mfa_enrolled_count
- api_calls_total, api_calls_4xx, api_calls_5xx
- avg_latency_ms, p99_latency_ms
- storage_bytes, audit_events_count, security_alerts_count
```

---

## 3. V031 USER-PRINCIPAL BRIDGE

### 3.1 Problem Statement

The current architecture has **implicit** user↔principal linking:
- Legacy users created via V003 system
- New principal-based auth via V018 system  
- User ID = Principal ID (same UUID) - but NOT enforced in DB

### 3.2 V031 Solution - Explicit Bridge

**Added to `users` table:**
| Column | Purpose |
|--------|---------|
| `principal_id` | Explicit FK to global_principals.id |
| `principal_linked_at` | Timestamp of bridge creation |
| `default_membership_id` | Quick access to tenant membership |
| `default_actor_id` | Current actor context |
| `default_actor_type` | Actor type (member, admin, etc.) |

**Added to `global_principals` table:**
| Column | Purpose |
|--------|---------|
| `linked_user_id` | Reverse link to users table |
| `linked_user_tenant_id` | Tenant context for the link |
| `linked_at` | When the link was established |

**New Table:**
| Table | Purpose |
|-------|---------|
| `user_principal_sync_log` | Audit trail of all bridge changes |

**Enhanced `sessions` table:**
- Added `principal_id`, `membership_id`, `actor_id` for fast lookups

### 3.3 V031 Benefits

1. **Query Performance** - No more JOIN through tenant_memberships to get principal context
2. **Data Integrity** - FK constraints can now enforce the relationship
3. **Auditability** - Sync log tracks all bridge changes
4. **Unified Auth** - Credentials can now link to principals directly

---

## 4. API DESIGN AUDIT

### 2.1 Current API Structure

```
/auth
  /password     - Password management
  /oauth        - OAuth flows
  /otp          - OTP verification
  /core         - Core auth operations
  /login        - Login endpoint

/iam           - Identity & Access Management
/governance    - RBAC & ABAC
/session       - Session management
/user          - User operations
/platform
  /oauth       - Platform OAuth
/jwks          - JWT signing keys
```

### 2.2 API Design Issues

| Issue | Severity | Location |
|-------|----------|----------|
| No rate limiting headers | MEDIUM | All endpoints |
| Missing API versioning | MEDIUM | All controllers |
| Inconsistent error responses | HIGH | Multiple controllers |
| No pagination on list endpoints | HIGH | User listing |
| Missing request ID tracking | MEDIUM | All endpoints |

---

## 5. ARCHITECTURE PATTERNS

### 3.1 Current Patterns Identified

| Pattern | Implementation | Status |
|---------|---------------|--------|
| **Repository Pattern** | `mysql-*.repository.ts` | ✅ Good |
| **Aggregate Root** | `User`, `Session` aggregates | ✅ Good |
| **Transactional Outbox** | `outbox_events` table | ✅ Good |
| **Event Sourcing** | `domain_events` table | ✅ Good |
| **Circuit Breaker** | `provider_health` with circuit_state | ✅ Good |
| **Optimistic Locking** | `version` column | ✅ Good |
| **Multi-Tenancy** | `tenant_id` on all tables | ✅ Good |
| **Encryption at Rest** | `VARBINARY` + KMS | ✅ Good |
| **Audit Logging** | `audit_logs` table | ✅ Good |

### 3.2 Architecture Refactor Recommendations

1. **Bridge user and principal systems** → Add migration to link `users` → `global_principals`
2. **Add Read Replica support** → Separate read/write pools
3. **Implement CQRS** → Separate read models for analytics
4. **Add CDC (Change Data Capture)** → For real-time sync

---

## 6. API BEST PRACTICES REVIEW

### 4.1 Current Compliance

| Practice | Status | Evidence |
|---------|--------|----------|
| **Consistent error codes** | ⚠️ PARTIAL | `DomainErrorCode` exists but not uniformly used |
| **Rate limiting** | ⚠️ PARTIAL | Redis-based middleware exists |
| **Idempotency** | ⚠️ PARTIAL | `communication_idempotency_keys` exists |
| **Pagination** | ❌ MISSING | No cursor-based pagination |
| **Request tracing** | ⚠️ PARTIAL | Tracer port exists but not wired everywhere |
| **Response caching** | ⚠️ PARTIAL | Cache port exists but underused |
| **Health checks** | ✅ EXISTS | `/health` endpoint |

---

## 7. ACTION ITEMS SUMMARY

| Priority | Action | Estimated Effort |
|----------|--------|-------------------|
| P0 | Create V029 migration file | ✅ DONE |
| P0 | Create V030 Meta Engineer telemetry migration | ✅ DONE |
| P0 | Add user→principal bridge migration (V031) | ✅ DONE |
| P1 | Wire security_events logging everywhere | 2 days |
| P1 | Wire api_metrics middleware | 2 days |
| P1 | Implement pagination on lists | 1 day |
| P1 | Wire request tracing everywhere | 1 day |
| P2 | Add consistent error response format | 2 days |
| P2 | Implement read replica routing | 2 days |

---

## 8. NEXT STEPS

1. **V029 Migration** — ✅ Complete - comprehensive user tracking
2. **V030 Migration** — ✅ Complete - Meta Engineer telemetry
3. **V031 Bridge Migration** — ✅ Complete - explicit user-principal linking
4. **Wire Security Events** — Add security event logging to auth flows
5. **Wire API Metrics** — Add metrics middleware to all endpoints
6. **API Design Audit** — Full endpoint review
7. **Architecture Patterns** — Implement refactors
8. **Best Practices** — Fix compliance gaps

---

*Report generated: 2026-05-12*

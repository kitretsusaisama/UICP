# Database Layer Comprehensive Analysis

**Analysis Date:** 2026-05-16

---

## 1. Migration Inventory

### 1.1 Migration Overview

The database consists of **34 migrations** (V001-V034) evolving from a basic schema versioning system to a comprehensive multi-tenant IAM platform.

| Migration | Purpose | Complexity | Risk |
|-----------|---------|------------|------|
| V001 | Schema versions table | Low | None |
| V002 | Tenants core table | Low | None |
| V003-V006 | Core identity (users, identities, credentials, sessions) | Medium | Data migration |
| V007-V011 | Auth artifacts (refresh tokens, JWT keys, OTP, devices, client apps) | Medium | Lock contention |
| V012-V017 | Governance and events (roles, permissions, ABAC, audit, SOC, events) | Low | None |
| V018-V022 | Principal and tenant runtime (global principals, auth methods, memberships) | Medium | FK validation |
| V023-V027 | Capabilities and communication (policies, extensions, OTP isolation) | Low | None |
| V029-V034 | Recent enhancements (user tracking, telemetry, API keys, platform identities) | Low | None |

---

## 2. Schema Analysis

### 2.1 Tenant Isolation Strategy

**Primary Isolation Pattern:** All tenant-scoped tables include `tenant_id` BINARY(16) NOT NULL column.

```sql
-- Users table (V003)
CREATE TABLE users (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  -- other columns
  PRIMARY KEY (id),
  KEY idx_tenant_status (tenant_id, status),
  KEY idx_tenant_created (tenant_id, created_at)
);
```

**Isolation Guarantees:**
- Every query in repository layer includes WHERE tenant_id = ?
- Composite indexes ensure tenant-scoped queries are efficient
- No cross-tenant queries in application layer

### 2.2 Core Tables

#### Tenants Table (V002)
```sql
CREATE TABLE tenants (
  id                      BINARY(16)    NOT NULL,
  slug                    VARCHAR(63)   NOT NULL,
  plan                    ENUM('free','pro','enterprise') NOT NULL,
  status                  ENUM('active','suspended','deleted') NOT NULL DEFAULT 'active',
  settings_enc            VARBINARY(4096),    -- Encrypted JSON
  settings_enc_kid        VARCHAR(36),         -- Key ID for encryption
  max_users               INT UNSIGNED        DEFAULT 1000,
  max_sessions_per_user   INT UNSIGNED        DEFAULT 5,
  mfa_policy              ENUM('optional','required','adaptive') DEFAULT 'optional',
  session_ttl_s           INT UNSIGNED        DEFAULT 86400,
  password_policy_json    JSON,
  allowed_domains_json    JSON,
  version                 INT UNSIGNED        DEFAULT 0,  -- Optimistic lock
  created_at              DATETIME(3),
  updated_at              DATETIME(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_slug (slug)
);
```

**Design Notes:**
- Settings encrypted at rest (proper for PII)
- Plan-based entitlements (free/pro/enterprise)
- MFA policy per tenant (optional/required/adaptive)
- Optimistic locking for concurrent updates

#### Users Table (V003)
```sql
CREATE TABLE users (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  display_name_enc        VARBINARY(512),
  display_name_enc_kid    VARCHAR(36),
  status                  ENUM('pending','active','suspended','deleted') DEFAULT 'pending',
  suspend_until           DATETIME(3),
  suspend_reason          VARCHAR(255),
  metadata_enc            VARBINARY(4096),
  metadata_enc_kid       VARCHAR(36),
  version                 INT UNSIGNED    DEFAULT 0,
  created_at              DATETIME(3),
  updated_at              DATETIME(3),
  PRIMARY KEY (id),
  KEY idx_tenant_status (tenant_id, status),
  KEY idx_tenant_created (tenant_id, created_at)
);
```

#### Identities Table (V004)
```sql
CREATE TABLE identities (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  type                    ENUM('email','phone','oauth') NOT NULL,
  value_enc               VARBINARY(1024),
  value_enc_kid           VARCHAR(36),
  value_hash              VARCHAR(64)   NOT NULL,    -- HMAC for lookup
  verified                BOOLEAN        NOT NULL DEFAULT FALSE,
  created_at              DATETIME(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_type_hash (tenant_id, type, value_hash),
  KEY idx_user (user_id)
);
```

#### Credentials Table (V005)
```sql
CREATE TABLE credentials (
  id                      BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  type                    ENUM('password','oauth','otp') NOT NULL,
  algorithm               VARCHAR(16)   NOT NULL,
  hash                    VARCHAR(255)  NOT NULL,    -- bcrypt hash
  salt                    VARCHAR(32),
  pepper_kid              VARCHAR(36),
  version                 INT UNSIGNED    DEFAULT 0,
  created_at              DATETIME(3),
  updated_at              DATETIME(3),
  PRIMARY KEY (id),
  KEY idx_user (user_id)
);
```

#### RBAC Tables (V012)
```sql
CREATE TABLE roles (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  name                    VARCHAR(64)   NOT NULL,
  description             VARCHAR(255),
  created_at              DATETIME(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_name (tenant_id, name)
);

CREATE TABLE permissions (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  resource                VARCHAR(64)   NOT NULL,
  action                  VARCHAR(64)   NOT NULL,
  created_at              DATETIME(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_resource_action (tenant_id, resource, action)
);
```

#### Outbox Events Table (V017)
```sql
CREATE TABLE outbox_events (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16),
  aggregate_type          VARCHAR(64)   NOT NULL,
  aggregate_id            BINARY(16)    NOT NULL,
  event_type              VARCHAR(64)   NOT NULL,
  event_payload_json      JSON NOT NULL,
  priority               INT UNSIGNED   NOT NULL DEFAULT 0,
  status                  ENUM('pending','processing','completed','failed') DEFAULT 'pending',
  attempts                INT UNSIGNED   NOT NULL DEFAULT 0,
  last_error             TEXT,
  created_at              DATETIME(3)   NOT NULL,
  processed_at           DATETIME(3),
  PRIMARY KEY (id),
  KEY idx_status (status, priority, created_at),
  KEY idx_tenant (tenant_id, aggregate_type, aggregate_id)
);
```

---

## 3. Index Coverage

| Table | Indexes | Coverage |
|-------|---------|----------|
| users | tenant+status, tenant+created_at | Good |
| identities | tenant+type+hash (unique), user_id | Good |
| credentials | user_id | Minimal |
| sessions | tenant+user, expires_at | Good |
| roles | tenant+name (unique) | Good |
| audit_logs | tenant+timestamp, tenant+actor | Good |
| outbox_events | status+priority+created_at, tenant+aggregate | Good |

---

## 4. Query Pattern Analysis

### 4.1 Common Queries

**User Lookup by Identity (O(1) via unique index):**
```sql
SELECT * FROM identities 
WHERE tenant_id = ? AND type = ? AND value_hash = ?
```

**User by ID with Hydration (N+1 pattern):**
```sql
SELECT * FROM users WHERE id = ? AND tenant_id = ?
SELECT * FROM identities WHERE user_id = ?
SELECT * FROM credentials WHERE user_id = ?
```

### 4.2 N+1 Issues

**MysqlUserRepository.findById():**
- Query 1: SELECT user WHERE id = ? AND tenant_id = ?
- Query 2: SELECT identities WHERE user_id = ?
- Query 3: SELECT credentials WHERE user_id = ?

**Recommendation:** Combine into single JOIN query for better performance.

---

## 5. Transaction Patterns

**User Creation (MysqlUserRepository.save()):**
```typescript
await connection.transaction(async (manager) => {
  // 1. Insert user
  // 2. Insert identity
  // 3. Insert credential
  // 4. Drain domain events and Insert outbox_events
});
```

**Consistency Guarantees:**
- Strong Consistency: User creation, credential updates
- Eventual Consistency: Audit log writes via outbox

---

## 6. Migration Safety

| Migration | Risk | Reason |
|-----------|------|--------|
| V003 (users) | Medium | Adds tenant_id, affects all users |
| V012 (roles) | Low | New tables |
| V017 (outbox) | Low | New tables |
| V025 (refresh token families) | Medium | Alters refresh token structure |

**Rollback Feasibility:** All migrations are additive (new tables, new columns) - can be rolled back safely.

---

## 7. Technical Debt

| Issue | Severity | Notes |
|-------|----------|-------|
| N+1 query pattern | High | User hydration should use JOIN |
| No partitioning strategy | Medium | Users table may need partitioning at scale |
| Missing credentials tenant index | Low | Could add tenant_id index |

---

## 8. Recommendations

### Priority 1
1. Implement JOIN-based user hydration in MysqlUserRepository
2. Add missing indexes for credentials table

### Priority 2
3. Consider partitioning strategy for users table at scale

### Priority 3
4. Add composite index for common audit log queries

---

## 9. Conclusion

The database schema is **well-designed** for a multi-tenant IAM platform:
- Proper tenant isolation via tenant_id columns
- Good indexing for common query patterns
- Optimistic locking for concurrent updates
- Outbox pattern for event-driven consistency

**Primary Concerns:**
1. N+1 query pattern in user hydration
2. No partitioning for large tables

The schema evolution shows careful consideration of backward compatibility and data integrity.
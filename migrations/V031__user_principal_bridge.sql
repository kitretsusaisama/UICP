-- V031__user_principal_bridge.sql
-- Explicit User ↔ Principal Bridge with Foreign Key Enforcement
-- Date: 2026-05-12
-- Purpose: Add explicit principal_id to users table with FK constraint

-- ============================================================================
-- ADD PRINCIPAL_ID TO USERS - Explicit bridge to global_principals
-- ============================================================================
-- The bridge is currently implicit (user.id = principal.id). This makes it explicit.
-- For legacy users: principal_id will equal users.id (self-referential bridge)
-- For new users: principal_id points to corresponding global_principal

ALTER TABLE users
ADD COLUMN principal_id BINARY(16) AFTER tenant_id,
ADD COLUMN principal_linked_at DATETIME(3) AFTER principal_id;

-- Create index for principal lookups
CREATE INDEX idx_users_principal ON users (tenant_id, principal_id);

-- ============================================================================
-- BACKFILL EXISTING USERS - Link each user to a principal with same ID
-- ============================================================================
-- For legacy users, the principal ID is the same as the user ID
-- This ensures backward compatibility with existing data
UPDATE users u
SET
  u.principal_id = u.id,
  u.principal_linked_at = u.created_at
WHERE u.principal_id IS NULL;

-- Make the column non-null after backfill
ALTER TABLE users MODIFY COLUMN principal_id BINARY(16) NOT NULL;
ALTER TABLE users MODIFY COLUMN principal_linked_at DATETIME(3) NOT NULL;

-- ============================================================================
-- ADD USER REFERENCE TO GLOBAL_PRINCIPALS - Reverse bridge
-- ============================================================================
ALTER TABLE global_principals
ADD COLUMN linked_user_id BINARY(16) AFTER primary_auth_method_id,
ADD COLUMN linked_user_tenant_id BINARY(16) AFTER linked_user_id,
ADD COLUMN linked_at DATETIME(3) AFTER linked_user_tenant_id;

-- Backfill: map each principal back to its user (where user.id = principal.id)
UPDATE global_principals gp
JOIN users u ON u.principal_id = gp.id
SET
  gp.linked_user_id = u.id,
  gp.linked_user_tenant_id = u.tenant_id,
  gp.linked_at = u.principal_linked_at
WHERE gp.linked_user_id IS NULL;

-- Add index for reverse lookups
CREATE INDEX idx_principal_linked_user ON global_principals (linked_user_tenant_id, linked_user_id);
CREATE INDEX idx_principal_linked_at ON global_principals (linked_at);

-- ============================================================================
-- TENANT MEMBERSHIP BRIDGE - Link users directly to their membership
-- ============================================================================
ALTER TABLE users
ADD COLUMN default_membership_id BINARY(16) AFTER principal_linked_at;

-- Backfill: find the primary membership for each user's principal in their tenant
UPDATE users u
JOIN global_principals gp ON gp.id = u.principal_id
JOIN tenant_memberships tm ON tm.principal_id = gp.id AND tm.tenant_id = u.tenant_id
SET u.default_membership_id = tm.id
WHERE u.default_membership_id IS NULL
  AND tm.status = 'active';

-- Add index
CREATE INDEX idx_users_membership ON users (tenant_id, default_membership_id);

-- ============================================================================
-- ADD ACTOR CONTEXT TO USERS - Quick access to current actor
-- ============================================================================
ALTER TABLE users
ADD COLUMN default_actor_id BINARY(16) AFTER default_membership_id,
ADD COLUMN default_actor_type VARCHAR(64) AFTER default_actor_id;

-- Backfill: get the default actor from the default membership
UPDATE users u
JOIN actor_profiles ap ON ap.membership_id = u.default_membership_id
SET
  u.default_actor_id = ap.id,
  u.default_actor_type = ap.actor_type
WHERE u.default_actor_id IS NULL
  AND ap.is_default = 1;

-- Add index for actor lookups
CREATE INDEX idx_users_actor ON users (tenant_id, default_actor_id);

-- ============================================================================
-- CREATE USER-PRINCIPAL SYNC LOG - Track changes to the bridge
-- ============================================================================
CREATE TABLE user_principal_sync_log (
  id                      BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  old_principal_id       BINARY(16),
  new_principal_id       BINARY(16)    NOT NULL,
  sync_type               ENUM('initial','user_created','principal_migrated','manual_link','unlink') NOT NULL,
  sync_status             ENUM('pending','completed','failed','reverted') NOT NULL DEFAULT 'pending',
  failure_reason          VARCHAR(255),
  synced_by               BINARY(16),
  synced_at               DATETIME(3),
  created_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (id),
  INDEX idx_user (user_id, created_at DESC),
  INDEX idx_tenant (tenant_id, created_at DESC),
  INDEX idx_status (sync_status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Mark all existing bridges as initially synced
INSERT INTO user_principal_sync_log (
  id, user_id, tenant_id, old_principal_id, new_principal_id,
  sync_type, sync_status, synced_by, synced_at, created_at
)
SELECT
  uuid_to_bin(UUID()),
  u.id,
  u.tenant_id,
  NULL,
  u.principal_id,
  'initial',
  'completed',
  NULL,
  u.principal_linked_at,
  NOW(3)
FROM users u
WHERE u.principal_id IS NOT NULL;

-- ============================================================================
-- ENHANCE SESSIONS - Add principal context for faster lookups
-- ============================================================================
ALTER TABLE sessions
ADD COLUMN principal_id BINARY(16) AFTER user_id,
ADD COLUMN membership_id BINARY(16) AFTER principal_id,
ADD COLUMN actor_id BINARY(16) AFTER membership_id;

-- Backfill: derive from user → principal → membership → actor chain
UPDATE sessions s
JOIN users u ON u.id = s.user_id AND u.tenant_id = s.tenant_id
SET
  s.principal_id = u.principal_id,
  s.membership_id = u.default_membership_id,
  s.actor_id = u.default_actor_id
WHERE s.principal_id IS NULL;

-- Add indexes for session lookups by principal/membership
CREATE INDEX idx_sessions_principal ON sessions (tenant_id, principal_id, created_at);
CREATE INDEX idx_sessions_membership ON sessions (tenant_id, membership_id, created_at);
CREATE INDEX idx_sessions_actor ON sessions (tenant_id, actor_id, created_at);

-- ============================================================================
-- CREDENTIAL LINK - Link credentials to principals for unified auth
-- ============================================================================
ALTER TABLE credentials
ADD COLUMN principal_id BINARY(16) AFTER user_id;

-- Backfill: derive from user
UPDATE credentials c
JOIN users u ON u.id = c.user_id
SET c.principal_id = u.principal_id
WHERE c.principal_id IS NULL;

CREATE INDEX idx_credentials_principal ON credentials (principal_id, created_at);

-- ============================================================================
-- ADD CONSTRAINTS - Enforce referential integrity
-- ============================================================================
-- Note: FK constraints need to be added after ensuring data integrity
-- These are commented out - uncomment after verifying data integrity

-- ALTER TABLE users
-- ADD CONSTRAINT fk_users_principal FOREIGN KEY (principal_id)
--   REFERENCES global_principals(id) ON DELETE RESTRICT ON UPDATE CASCADE;

-- ALTER TABLE global_principals
-- ADD CONSTRAINT fk_principal_user FOREIGN KEY (linked_user_id, linked_user_tenant_id)
--   REFERENCES users(id, tenant_id) ON DELETE SET NULL ON UPDATE CASCADE;

-- ============================================================================
-- INSERT DEFAULT SCHEMA VERSION
-- ============================================================================
-- INSERT INTO schema_versions (version, description, checksum, applied_at, applied_by, duration_ms)
-- VALUES (
--   31,
--   'Add explicit user-principal bridge with FK enforcement and sync logging',
--   SHA2('V031__user_principal_bridge', 256),
--   NOW(3),
--   'system',
--   0
-- );
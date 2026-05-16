-- V029__enhance_user_tracking.sql
-- Enhanced User Tracking and Audit Fields for UICP
-- Date: 2026-05-12
-- Purpose: Add missing audit fields for comprehensive user tracking and security forensics

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

-- Add indexes for new tracking fields
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

-- Add index for session analysis
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

  PRIMARY KEY (id, created_at),
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
-- PASSWORD HISTORY - Track password hashes for rotation enforcement
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

-- Backfill first_seen_at for existing devices (sets to created_at)
UPDATE devices SET first_seen_at = created_at WHERE first_seen_at IS NULL;
ALTER TABLE devices MODIFY COLUMN first_seen_at DATETIME(3) NOT NULL;

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
  failed_login_count       INT UNSIGNED  NOT NULL DEFAULT 0,
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

-- ============================================================================
-- INSERT DEFAULT SCHEMA VERSION
-- ============================================================================
-- INSERT INTO schema_versions (version, description, checksum, applied_at, applied_by, duration_ms)
-- VALUES (
--   29,
--   'Add comprehensive user tracking, login history, and audit fields',
--   SHA2('V029__enhance_user_tracking', 256),
--   NOW(3),
--   'system',
--   0
--);

-- V006: Create sessions table (partitioned by RANGE(expires_at))
CREATE TABLE sessions (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  ip_hash                 BINARY(32)    NOT NULL,
  ua_browser              VARCHAR(64),
  ua_os                   VARCHAR(64),
  ua_device_type          ENUM('desktop','mobile','tablet','bot','unknown') NOT NULL DEFAULT 'unknown',
  device_fingerprint      VARCHAR(64),
  mfa_verified            TINYINT(1)    NOT NULL DEFAULT 0,
  mfa_verified_at         DATETIME(3),
  access_token_jti        BINARY(16),
  status                  ENUM('created','mfa_pending','active','expired','revoked') NOT NULL DEFAULT 'created',
  revoked_reason          VARCHAR(255),
  expires_at              DATETIME(3)   NOT NULL,
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id, expires_at),
  KEY idx_user_id (user_id),
  KEY idx_tenant_user (tenant_id, user_id)
);

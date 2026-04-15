-- V002: Create tenants table
CREATE TABLE tenants (
  id                      BINARY(16)    NOT NULL,
  slug                    VARCHAR(63)   NOT NULL,
  plan                    ENUM('free','pro','enterprise') NOT NULL,
  status                  ENUM('active','suspended','deleted') NOT NULL DEFAULT 'active',
  settings_enc            VARBINARY(4096),
  settings_enc_kid        VARCHAR(36),
  max_users               INT UNSIGNED  NOT NULL DEFAULT 1000,
  max_sessions_per_user   INT UNSIGNED  NOT NULL DEFAULT 5,
  mfa_policy              ENUM('optional','required','adaptive') NOT NULL DEFAULT 'optional',
  session_ttl_s           INT UNSIGNED  NOT NULL DEFAULT 86400,
  password_policy_json    JSON,
  allowed_domains_json    JSON,
  version                 INT UNSIGNED  NOT NULL DEFAULT 0,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_slug (slug)
);

-- V007: Create refresh_tokens table (partitioned by RANGE(expires_at))
CREATE TABLE refresh_tokens (
  jti                     BINARY(16)    NOT NULL,
  family_id               BINARY(16)    NOT NULL,
  parent_jti              BINARY(16),
  user_id                 BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  revoked                 TINYINT(1)    NOT NULL DEFAULT 0,
  revoked_at              DATETIME(3),
  expires_at              DATETIME(3)   NOT NULL,
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (jti, expires_at),
  KEY idx_family_id (family_id),
  KEY idx_user_id (user_id)
);

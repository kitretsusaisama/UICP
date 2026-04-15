-- V010: Create devices table
CREATE TABLE devices (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  fingerprint             VARCHAR(64)   NOT NULL,
  name                    VARCHAR(128),
  trusted                 TINYINT(1)    NOT NULL DEFAULT 0,
  trusted_at              DATETIME(3),
  last_seen_at            DATETIME(3)   NOT NULL,
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_user_fingerprint (user_id, fingerprint),
  KEY idx_tenant_user (tenant_id, user_id)
);

-- V003: Create users table (partitioned by HASH(tenant_id))
CREATE TABLE users (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  display_name_enc        VARBINARY(512),
  display_name_enc_kid    VARCHAR(36),
  status                  ENUM('pending','active','suspended','deleted') NOT NULL DEFAULT 'pending',
  suspend_until           DATETIME(3),
  suspend_reason          VARCHAR(255),
  metadata_enc            VARBINARY(4096),
  metadata_enc_kid        VARCHAR(36),
  version                 INT UNSIGNED  NOT NULL DEFAULT 0,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  KEY idx_tenant_status (tenant_id, status),
  KEY idx_tenant_created (tenant_id, created_at)
);

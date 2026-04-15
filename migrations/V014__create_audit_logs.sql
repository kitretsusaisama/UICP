-- V014: Create audit_logs table (partitioned by RANGE(created_at))
CREATE TABLE audit_logs (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  actor_id                BINARY(16),
  actor_type              ENUM('user','system','admin') NOT NULL DEFAULT 'user',
  action                  VARCHAR(128)  NOT NULL,
  resource_type           VARCHAR(64)   NOT NULL,
  resource_id             BINARY(16),
  metadata_enc            VARBINARY(4096),
  metadata_enc_kid        VARCHAR(36),
  ip_hash                 BINARY(32),
  checksum                BINARY(32)    NOT NULL,
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id, created_at),
  KEY idx_tenant_time (tenant_id, created_at),
  KEY idx_actor (tenant_id, actor_id, created_at),
  KEY idx_resource (tenant_id, resource_type, resource_id, created_at)
);

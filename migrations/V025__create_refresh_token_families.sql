CREATE TABLE refresh_token_families (
  id                      BINARY(16)    NOT NULL,
  principal_id            BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  membership_id           BINARY(16),
  session_id              BINARY(16),
  status                  ENUM('active','revoked','compromised') NOT NULL DEFAULT 'active',
  revoked_reason          VARCHAR(255),
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  KEY idx_principal_tenant (principal_id, tenant_id, status)
);

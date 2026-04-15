-- V011: Create client_apps table
CREATE TABLE client_apps (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  name                    VARCHAR(128)  NOT NULL,
  client_id               VARCHAR(64)   NOT NULL,
  client_secret_hash      VARCHAR(255),
  redirect_uris_json      JSON          NOT NULL,
  allowed_scopes_json     JSON          NOT NULL,
  grant_types_json        JSON          NOT NULL,
  status                  ENUM('active','suspended','deleted') NOT NULL DEFAULT 'active',
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_client_id (client_id),
  KEY idx_tenant (tenant_id)
);

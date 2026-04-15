CREATE TABLE tenant_domains (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  domain                  VARCHAR(255)  NOT NULL,
  kind                    ENUM('subdomain','custom_domain') NOT NULL DEFAULT 'subdomain',
  verified                TINYINT(1)    NOT NULL DEFAULT 0,
  is_primary              TINYINT(1)    NOT NULL DEFAULT 0,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_domain (domain),
  KEY idx_tenant_primary (tenant_id, is_primary)
);

CREATE TABLE tenant_entitlements (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  entitlement_key         VARCHAR(128)  NOT NULL,
  status                  ENUM('enabled','disabled') NOT NULL DEFAULT 'enabled',
  quota_limit             BIGINT,
  quota_used              BIGINT        NOT NULL DEFAULT 0,
  config_json             JSON,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_entitlement (tenant_id, entitlement_key)
);

CREATE TABLE tenant_runtime_settings (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  tenant_type             VARCHAR(64)   NOT NULL DEFAULT 'workspace',
  isolation_tier          ENUM('shared','isolated_schema','isolated_db','dedicated_runtime') NOT NULL DEFAULT 'shared',
  runtime_status          ENUM('active','maintenance','suspended') NOT NULL DEFAULT 'active',
  settings_json           JSON,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_runtime (tenant_id)
);

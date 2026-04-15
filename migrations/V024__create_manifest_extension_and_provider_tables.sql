CREATE TABLE module_manifests (
  id                      BINARY(16)    NOT NULL,
  module_key              VARCHAR(128)  NOT NULL,
  version                 VARCHAR(64)   NOT NULL,
  manifest_json           JSON          NOT NULL,
  status                  ENUM('draft','active','archived') NOT NULL DEFAULT 'active',
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_module_version (module_key, version)
);

CREATE TABLE tenant_manifest_overrides (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  module_key              VARCHAR(128)  NOT NULL,
  version                 VARCHAR(64)   NOT NULL,
  override_json           JSON          NOT NULL,
  status                  ENUM('draft','active','archived') NOT NULL DEFAULT 'active',
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_module_override (tenant_id, module_key, version)
);

CREATE TABLE effective_manifest_cache (
  tenant_id               BINARY(16)    NOT NULL,
  version_hash            CHAR(64)      NOT NULL,
  manifest_json           JSON          NOT NULL,
  generated_at            DATETIME(3)   NOT NULL,
  PRIMARY KEY (tenant_id, version_hash)
);

CREATE TABLE extension_handlers (
  id                      BINARY(16)    NOT NULL,
  extension_key           VARCHAR(128)  NOT NULL,
  kind                    VARCHAR(64)   NOT NULL,
  runtime_target          ENUM('shared','isolated') NOT NULL DEFAULT 'shared',
  contract_version        VARCHAR(32)   NOT NULL,
  handler_ref             VARCHAR(255)  NOT NULL,
  status                  ENUM('active','disabled') NOT NULL DEFAULT 'active',
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_extension_handler (extension_key, kind, contract_version)
);

CREATE TABLE extension_bindings (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  module_key              VARCHAR(128)  NOT NULL,
  extension_point         VARCHAR(128)  NOT NULL,
  handler_id              BINARY(16)    NOT NULL,
  config_json             JSON,
  status                  ENUM('active','disabled') NOT NULL DEFAULT 'active',
  version                 INT UNSIGNED  NOT NULL DEFAULT 1,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_extension_binding (tenant_id, module_key, extension_point)
);

CREATE TABLE provider_configs (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16),
  channel                 ENUM('sms','email') NOT NULL,
  provider_key            VARCHAR(64)   NOT NULL,
  status                  ENUM('active','disabled') NOT NULL DEFAULT 'active',
  credentials_ref         VARCHAR(255),
  sender_config_json      JSON,
  timeout_ms              INT UNSIGNED  NOT NULL DEFAULT 5000,
  circuit_policy_json     JSON,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  KEY idx_provider_channel (tenant_id, channel, status)
);

CREATE TABLE provider_routing_rules (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16),
  channel                 ENUM('sms','email') NOT NULL,
  purpose                 VARCHAR(64)   NOT NULL,
  country_code            VARCHAR(8),
  priority                INT           NOT NULL DEFAULT 100,
  provider_key            VARCHAR(64)   NOT NULL,
  fallback_on_error       TINYINT(1)    NOT NULL DEFAULT 1,
  enabled                 TINYINT(1)    NOT NULL DEFAULT 1,
  version                 INT UNSIGNED  NOT NULL DEFAULT 1,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  KEY idx_provider_routing (tenant_id, channel, purpose, enabled, priority)
);

CREATE TABLE config_versions (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16),
  scope                   VARCHAR(64)   NOT NULL,
  version_hash            CHAR(64)      NOT NULL,
  metadata_json           JSON,
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  KEY idx_scope_created (tenant_id, scope, created_at)
);

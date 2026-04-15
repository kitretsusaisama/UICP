CREATE TABLE capability_catalog (
  id                      BINARY(16)    NOT NULL,
  capability_key          VARCHAR(128)  NOT NULL,
  description             VARCHAR(255),
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_capability_key (capability_key)
);

CREATE TABLE role_bundles (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16),
  bundle_key              VARCHAR(128)  NOT NULL,
  description             VARCHAR(255),
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_bundle (tenant_id, bundle_key)
);

CREATE TABLE role_bundle_capabilities (
  role_bundle_id          BINARY(16)    NOT NULL,
  capability_id           BINARY(16)    NOT NULL,
  PRIMARY KEY (role_bundle_id, capability_id)
);

CREATE TABLE actor_role_bindings (
  actor_profile_id        BINARY(16)    NOT NULL,
  role_bundle_id          BINARY(16)    NOT NULL,
  granted_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (actor_profile_id, role_bundle_id)
);

CREATE TABLE policy_templates (
  id                      BINARY(16)    NOT NULL,
  template_key            VARCHAR(128)  NOT NULL,
  effect                  ENUM('allow','deny') NOT NULL,
  priority                INT           NOT NULL DEFAULT 0,
  subject_condition       TEXT          NOT NULL,
  resource_condition      TEXT          NOT NULL,
  action_condition        TEXT          NOT NULL,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_policy_template_key (template_key)
);

CREATE TABLE tenant_policy_bindings (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  policy_template_id      BINARY(16)    NOT NULL,
  enabled                 TINYINT(1)    NOT NULL DEFAULT 1,
  priority_override       INT,
  version                 INT UNSIGNED  NOT NULL DEFAULT 1,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_policy_binding (tenant_id, policy_template_id)
);

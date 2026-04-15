-- V013: Create abac_policies table
CREATE TABLE abac_policies (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  name                    VARCHAR(128)  NOT NULL,
  effect                  ENUM('allow','deny') NOT NULL,
  priority                INT           NOT NULL DEFAULT 0,
  subject_condition       TEXT          NOT NULL,
  resource_condition      TEXT          NOT NULL,
  action_condition        TEXT          NOT NULL,
  enabled                 TINYINT(1)    NOT NULL DEFAULT 1,
  version                 INT UNSIGNED  NOT NULL DEFAULT 0,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  KEY idx_tenant_priority (tenant_id, priority DESC, enabled)
);

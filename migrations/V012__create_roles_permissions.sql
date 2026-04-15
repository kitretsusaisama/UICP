-- V012: Create roles, permissions, role_permissions, and user_roles tables

CREATE TABLE roles (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  name                    VARCHAR(64)   NOT NULL,
  description             VARCHAR(255),
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_name (tenant_id, name)
);

CREATE TABLE permissions (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  resource                VARCHAR(64)   NOT NULL,
  action                  VARCHAR(64)   NOT NULL,
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_resource_action (tenant_id, resource, action)
);

CREATE TABLE role_permissions (
  role_id                 BINARY(16)    NOT NULL,
  permission_id           BINARY(16)    NOT NULL,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
  user_id                 BINARY(16)    NOT NULL,
  role_id                 BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  granted_at              DATETIME(3)   NOT NULL,
  granted_by              BINARY(16),
  PRIMARY KEY (user_id, role_id),
  KEY idx_tenant_user (tenant_id, user_id)
);

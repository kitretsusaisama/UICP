CREATE TABLE tenant_memberships (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  principal_id            BINARY(16)    NOT NULL,
  status                  ENUM('invited','active','suspended','revoked') NOT NULL DEFAULT 'active',
  joined_at               DATETIME(3)   NOT NULL,
  ended_at                DATETIME(3),
  invited_by_principal_id BINARY(16),
  metadata_enc            VARBINARY(4096),
  metadata_enc_kid        VARCHAR(36),
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_principal (tenant_id, principal_id),
  KEY idx_principal_status (principal_id, status)
);

CREATE TABLE actor_profiles (
  id                      BINARY(16)    NOT NULL,
  membership_id           BINARY(16)    NOT NULL,
  actor_type              VARCHAR(64)   NOT NULL,
  display_name_enc        VARBINARY(512),
  display_name_enc_kid    VARCHAR(36),
  status                  ENUM('active','disabled') NOT NULL DEFAULT 'active',
  is_default              TINYINT(1)    NOT NULL DEFAULT 0,
  metadata_enc            VARBINARY(4096),
  metadata_enc_kid        VARCHAR(36),
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_membership_actor_type (membership_id, actor_type),
  KEY idx_membership_default (membership_id, is_default)
);

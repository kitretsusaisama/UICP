-- V004: Create identities table (partitioned by HASH(tenant_id))
CREATE TABLE identities (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  type                    ENUM('email','phone','google','github','apple','microsoft') NOT NULL,
  value_enc               VARBINARY(512) NOT NULL,
  value_enc_kid           VARCHAR(36)   NOT NULL,
  value_hash              BINARY(32)    NOT NULL,
  provider_sub            VARCHAR(255),
  provider_data_enc       VARBINARY(4096),
  provider_data_enc_kid   VARCHAR(36),
  verified                TINYINT(1)    NOT NULL DEFAULT 0,
  verified_at             DATETIME(3),
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_type_hash (tenant_id, type, value_hash),
  KEY idx_user_id (user_id),
  KEY idx_provider_sub (tenant_id, type, provider_sub)
);

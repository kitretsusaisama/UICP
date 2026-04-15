CREATE TABLE global_principals (
  id                      BINARY(16)    NOT NULL,
  status                  ENUM('pending','active','suspended','deleted') NOT NULL DEFAULT 'pending',
  risk_state              ENUM('low','medium','high','blocked') NOT NULL DEFAULT 'low',
  primary_auth_method_id  BINARY(16),
  metadata_enc            VARBINARY(4096),
  metadata_enc_kid        VARCHAR(36),
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  KEY idx_status_created (status, created_at)
);

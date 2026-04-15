-- V008: Create jwt_signing_keys table
CREATE TABLE jwt_signing_keys (
  kid                     VARCHAR(36)   NOT NULL,
  private_key_enc         VARBINARY(8192) NOT NULL,
  private_key_enc_kid     VARCHAR(36)   NOT NULL,
  public_jwk              JSON          NOT NULL,
  algorithm               VARCHAR(16)   NOT NULL DEFAULT 'RS256',
  key_size                SMALLINT UNSIGNED NOT NULL DEFAULT 4096,
  status                  ENUM('active','deprecated','revoked') NOT NULL DEFAULT 'active',
  created_at              DATETIME(3)   NOT NULL,
  deprecated_at           DATETIME(3),
  revoked_at              DATETIME(3),
  PRIMARY KEY (kid),
  KEY idx_status (status)
);

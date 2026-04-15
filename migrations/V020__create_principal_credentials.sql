CREATE TABLE principal_credentials (
  id                      BINARY(16)    NOT NULL,
  principal_id            BINARY(16)    NOT NULL,
  auth_method_id          BINARY(16),
  algorithm               ENUM('bcrypt_v1','argon2id_v1') NOT NULL DEFAULT 'bcrypt_v1',
  hash                    VARCHAR(255)  NOT NULL,
  rounds                  TINYINT UNSIGNED NOT NULL,
  pepper_version          VARCHAR(32)   NOT NULL DEFAULT 'v1',
  pwned                   TINYINT(1)    NOT NULL DEFAULT 0,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  KEY idx_principal (principal_id),
  KEY idx_auth_method (auth_method_id)
);

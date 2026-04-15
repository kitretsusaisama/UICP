-- V005: Create credentials table
CREATE TABLE credentials (
  id                      BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  hash                    VARCHAR(255)  NOT NULL,
  algorithm               ENUM('bcrypt_v1','argon2id_v1') NOT NULL DEFAULT 'bcrypt_v1',
  rounds                  TINYINT UNSIGNED NOT NULL,
  prev_hash               VARCHAR(255),
  prev_expires_at         DATETIME(3),
  pwned                   TINYINT(1)    NOT NULL DEFAULT 0,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_user_id (user_id)
);

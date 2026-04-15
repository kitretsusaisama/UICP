-- V009: Create otp_attempts table (partitioned by RANGE(created_at))
CREATE TABLE otp_attempts (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  purpose                 ENUM('identity_verification','password_reset','mfa','login') NOT NULL,
  channel                 ENUM('email','sms') NOT NULL,
  success                 TINYINT(1)    NOT NULL DEFAULT 0,
  ip_hash                 BINARY(32)    NOT NULL,
  created_at              DATETIME(3)   NOT NULL,
  PRIMARY KEY (id, created_at),
  KEY idx_user_purpose (user_id, purpose, created_at)
);

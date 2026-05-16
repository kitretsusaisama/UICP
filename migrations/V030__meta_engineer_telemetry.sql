-- V030__meta_engineer_telemetry.sql
-- Meta Engineer Style: Comprehensive Security, Performance & Behavior Telemetry
-- Date: 2026-05-12
-- Purpose: Enterprise-grade telemetry for security, ops, and product analytics

-- V030: Meta Engineer Style Telemetry

-- ============================================================================
-- SECURITY TELEMETRY
-- ============================================================================
CREATE TABLE security_events (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  user_id                 BINARY(16),
  principal_id            BINARY(16),
  session_id              BINARY(16),
  event_type              ENUM(
    'login_success','login_failed','login_blocked','mfa_success','mfa_failed',
    'password_changed','password_reset_requested','password_reset_completed',
    'account_locked','account_unlocked','account_suspended','account_reactivated',
    'credential_stuffed','brute_force_attempt','anomalous_ip','anomalous_geo',
    'session_hijack_suspected','token_reused','jwt_invalid','refresh_token_rotated',
    'rate_limit_exceeded','api_key_rotated','oauth_token_refreshed','oauth_revoked',
    'impersonation_detected','privilege_escalation','permission_denied','admin_action'
  ) NOT NULL,
  severity                ENUM('info','warning','medium','high','critical') NOT NULL DEFAULT 'info',
  ip_hash                 BINARY(32),
  ip_country              VARCHAR(2),
  ip_city                 VARCHAR(128),
  user_agent              VARCHAR(512),
  device_fingerprint      VARCHAR(64),
  geo_delta_seconds       INT,
  ip_change_detected      TINYINT(1)    NOT NULL DEFAULT 0,
  time_delta_from_last    INT,
  failure_count_window    INT,
  details_json            JSON,
  threat_score            DECIMAL(4,3),
  detected_by             ENUM('rules','ml_model','heuristic','manual') NOT NULL DEFAULT 'rules',
  created_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (id, created_at),
  INDEX idx_tenant_time (tenant_id, created_at),
  INDEX idx_user_time (user_id, created_at),
  INDEX idx_event_type (tenant_id, event_type, created_at),
  INDEX idx_severity (tenant_id, severity, created_at),
  INDEX idx_threat_score (tenant_id, threat_score DESC, created_at),
  INDEX idx_ip_country (tenant_id, ip_country, created_at),
  INDEX idx_principal_time (principal_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
PARTITION BY RANGE (TO_DAYS(created_at)) (
  PARTITION p_default VALUES LESS THAN MAXVALUE
);

-- ============================================================================
-- API PERFORMANCE METRICS
-- ============================================================================
CREATE TABLE api_metrics (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  user_id                 BINARY(16),
  principal_id            BINARY(16),
  method                  VARCHAR(8)    NOT NULL,
  path                    VARCHAR(256)  NOT NULL,
  path_template           VARCHAR(256),
  status_code             SMALLINT UNSIGNED NOT NULL,
  latency_ms              INT UNSIGNED  NOT NULL,
  db_query_count          INT UNSIGNED  NOT NULL DEFAULT 0,
  db_query_time_ms        INT UNSIGNED  NOT NULL DEFAULT 0,
  cache_hit               TINYINT(1)    NOT NULL DEFAULT 0,
  external_api_calls      INT UNSIGNED  NOT NULL DEFAULT 0,
  external_api_time_ms    INT UNSIGNED  NOT NULL DEFAULT 0,
  request_size_bytes      INT UNSIGNED,
  response_size_bytes     INT UNSIGNED,
  user_agent              VARCHAR(512),
  ip_hash                 BINARY(32),
  correlation_id          VARCHAR(64),
  error_type              VARCHAR(64),
  error_message           VARCHAR(512),
  created_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (id, created_at),
  INDEX idx_tenant_time (tenant_id, created_at),
  INDEX idx_path_time (path_template, created_at),
  INDEX idx_user_time (user_id, created_at),
  INDEX idx_status_time (tenant_id, status_code, created_at),
  INDEX idx_latency_p99 (tenant_id, path_template, latency_ms, created_at),
  INDEX idx_correlation (correlation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
PARTITION BY RANGE (TO_DAYS(created_at)) (
  PARTITION p_default VALUES LESS THAN MAXVALUE
);

-- ============================================================================
-- TENANT ANALYTICS
-- ============================================================================
CREATE TABLE tenant_metrics (
  tenant_id               BINARY(16)    NOT NULL,
  date_key                DATE          NOT NULL,
  active_users            INT UNSIGNED  NOT NULL DEFAULT 0,
  active_principals       INT UNSIGNED  NOT NULL DEFAULT 0,
  new_users               INT UNSIGNED  NOT NULL DEFAULT 0,
  new_principals          INT UNSIGNED  NOT NULL DEFAULT 0,
  deleted_users           INT UNSIGNED  NOT NULL DEFAULT 0,
  total_logins            INT UNSIGNED  NOT NULL DEFAULT 0,
  failed_logins           INT UNSIGNED  NOT NULL DEFAULT 0,
  mfa_enrolled_count      INT UNSIGNED  NOT NULL DEFAULT 0,
  active_sessions         INT UNSIGNED  NOT NULL DEFAULT 0,
  api_calls_total         BIGINT UNSIGNED NOT NULL DEFAULT 0,
  api_calls_4xx           BIGINT UNSIGNED NOT NULL DEFAULT 0,
  api_calls_5xx           BIGINT UNSIGNED NOT NULL DEFAULT 0,
  avg_latency_ms          DECIMAL(10,2),
  p99_latency_ms          INT UNSIGNED,
  storage_bytes           BIGINT UNSIGNED NOT NULL DEFAULT 0,
  audit_events_count      INT UNSIGNED  NOT NULL DEFAULT 0,
  security_alerts_count   INT UNSIGNED  NOT NULL DEFAULT 0,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (tenant_id, date_key),
  INDEX idx_date (date_key),
  INDEX idx_active_users (tenant_id, active_users DESC, date_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- RATE LIMIT EVENTS
-- ============================================================================
CREATE TABLE rate_limit_events (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  user_id                 BINARY(16),
  principal_id            BINARY(16),
  ip_hash                 BINARY(32),
  endpoint                VARCHAR(256)  NOT NULL,
  limit_key               VARCHAR(128)  NOT NULL,
  limit_type              ENUM('user','ip','tenant','global') NOT NULL,
  limit_window            ENUM('second','minute','hour','day') NOT NULL,
  limit_value             INT UNSIGNED  NOT NULL,
  current_count           INT UNSIGNED  NOT NULL,
  blocked                 TINYINT(1)    NOT NULL DEFAULT 0,
  reset_at                DATETIME(3)   NOT NULL,
  user_agent              VARCHAR(512),
  created_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (id, created_at),
  INDEX idx_tenant_time (tenant_id, created_at),
  INDEX idx_user_time (user_id, created_at),
  INDEX idx_endpoint (tenant_id, endpoint, created_at),
  INDEX idx_blocked (tenant_id, blocked, created_at),
  INDEX idx_ip_time (ip_hash, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
PARTITION BY RANGE (TO_DAYS(created_at)) (
  PARTITION p_default VALUES LESS THAN MAXVALUE
);

-- ============================================================================
-- THREAT INTELLIGENCE
-- ============================================================================
CREATE TABLE threat_intelligence (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  ioc_type                ENUM('ip','email','phone','user_agent','device_fingerprint','asn') NOT NULL,
  ioc_value               VARCHAR(512)  NOT NULL,
  threat_category         ENUM('credential_stuffing','brute_force','scraping','ddos','spam','phishing','malware','proxy','vpn','tor_exit') NOT NULL,
  confidence_score        DECIMAL(3,2)  NOT NULL,
  first_seen_at           DATETIME(3)   NOT NULL,
  last_seen_at            DATETIME(3)   NOT NULL,
  event_count             INT UNSIGNED  NOT NULL DEFAULT 1,
  related_user_ids        JSON,
  related_ip_hashes       JSON,
  geo_countries           JSON,
  is_whitelisted          TINYINT(1)    NOT NULL DEFAULT 0,
  whitelist_reason        VARCHAR(255),
  threat_score            DECIMAL(4,3),
  metadata_json           JSON,
  created_at              DATETIME(3)   NOT NULL,
  updated_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (id),
  UNIQUE KEY uq_ioc (tenant_id, ioc_type, ioc_value(255)),
  INDEX idx_threat_category (tenant_id, threat_category, last_seen_at),
  INDEX idx_confidence (tenant_id, confidence_score DESC),
  INDEX idx_first_seen (tenant_id, first_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- USER BEHAVIOR ANALYTICS
-- ============================================================================
CREATE TABLE user_behavior_events (
  id                      BINARY(16)    NOT NULL,
  tenant_id               BINARY(16)    NOT NULL,
  user_id                 BINARY(16)    NOT NULL,
  principal_id            BINARY(16),
  session_id              BINARY(16),
  event_name              VARCHAR(128)  NOT NULL,
  event_category          ENUM('auth','onboarding','profile','settings','api_usage','feature','admin','support') NOT NULL,
  event_source            ENUM('web','mobile','api','system') NOT NULL,
  step_number             TINYINT UNSIGNED,
  funnel_name             VARCHAR(128),
  properties_json         JSON,
  latency_ms              INT UNSIGNED,
  result                  ENUM('success','failed','abandoned','skipped') NOT NULL DEFAULT 'success',
  error_code              VARCHAR(64),
  ip_hash                 BINARY(32),
  user_agent              VARCHAR(512),
  created_at              DATETIME(3)   NOT NULL,

  PRIMARY KEY (id, created_at),
  INDEX idx_user_time (user_id, created_at),
  INDEX idx_tenant_time (tenant_id, created_at),
  INDEX idx_event_name (tenant_id, event_name, created_at),
  INDEX idx_funnel (tenant_id, funnel_name, step_number, created_at),
  INDEX idx_category (tenant_id, event_category, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
PARTITION BY RANGE (TO_DAYS(created_at)) (
  PARTITION p_default VALUES LESS THAN MAXVALUE
);

-- ============================================================================
-- SESSION INTELLIGENCE
-- ============================================================================
ALTER TABLE sessions
ADD COLUMN session_token_hash BINARY(32) AFTER device_fingerprint,
ADD COLUMN previous_ip_hash BINARY(32) AFTER session_token_hash,
ADD COLUMN ip_change_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER previous_ip_hash,
ADD COLUMN device_change_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER ip_change_count,
ADD COLUMN geo_anomaly_score DECIMAL(3,2) AFTER device_change_count,
ADD COLUMN last_activity_at DATETIME(3) AFTER geo_anomaly_score,
ADD COLUMN activity_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER last_activity_at,
ADD COLUMN avg_action_latency_ms INT UNSIGNED AFTER activity_count,
ADD COLUMN is_anonymous TINYINT(1) NOT NULL DEFAULT 0 AFTER avg_action_latency_ms,
ADD COLUMN client_version VARCHAR(32) AFTER is_anonymous,
ADD COLUMN client_platform VARCHAR(32) AFTER client_version;

CREATE INDEX idx_sessions_activity ON sessions (tenant_id, user_id, last_activity_at);
CREATE INDEX idx_sessions_anomaly ON sessions (tenant_id, geo_anomaly_score DESC, created_at);
CREATE INDEX idx_sessions_anonymous ON sessions (tenant_id, is_anonymous, created_at);

-- ============================================================================
-- ENHANCE AUDIT_LOGS
-- ============================================================================
ALTER TABLE audit_logs
ADD COLUMN user_id BINARY(16) AFTER actor_id,
ADD COLUMN principal_id BINARY(16) AFTER user_id,
ADD COLUMN session_id BINARY(16) AFTER principal_id,
ADD COLUMN correlation_id VARCHAR(64) AFTER session_id,
ADD COLUMN request_method VARCHAR(8) AFTER correlation_id,
ADD COLUMN request_path VARCHAR(256) AFTER request_method,
ADD COLUMN request_body_hash BINARY(32) AFTER request_path,
ADD COLUMN response_status SMALLINT UNSIGNED AFTER request_body_hash,
ADD COLUMN user_agent VARCHAR(512) AFTER response_status,
ADD COLUMN geo_country VARCHAR(2) AFTER user_agent,
ADD COLUMN auth_context_json JSON AFTER geo_country;

CREATE INDEX idx_audit_user_time ON audit_logs (tenant_id, user_id, created_at);
CREATE INDEX idx_audit_principal_time ON audit_logs (tenant_id, principal_id, created_at);
CREATE INDEX idx_audit_correlation ON audit_logs (correlation_id);
CREATE INDEX idx_audit_response_status ON audit_logs (tenant_id, response_status, created_at);

-- ============================================================================
-- ENHANCE SOC_ALERTS
-- ============================================================================
ALTER TABLE soc_alerts
ADD COLUMN attack_type ENUM('credential_stuffing','brute_force','account_takeover','insider_threat','api_abuse','ddos','phishing','scraping','privilege_escalation','data_exfiltration') AFTER kill_chain_stage,
ADD COLUMN primary_ioc_type ENUM('ip','email','phone','user_agent','device_fingerprint','account') AFTER attack_type,
ADD COLUMN primary_ioc_value VARCHAR(512) AFTER primary_ioc_type,
ADD COLUMN related_iocs_json JSON AFTER primary_ioc_value,
ADD COLUMN attacker_profile_json JSON AFTER related_iocs_json,
ADD COLUMN victim_user_ids_json JSON AFTER attacker_profile_json,
ADD COLUMN affected_sessions_json JSON AFTER victim_user_ids_json,
ADD COLUMN affected_ips_json JSON AFTER affected_sessions_json,
ADD COLUMN recommended_action VARCHAR(128) AFTER affected_ips_json,
ADD COLUMN auto_resolved TINYINT(1) NOT NULL DEFAULT 0 AFTER recommended_action,
ADD COLUMN ml_model_name VARCHAR(64) AFTER auto_resolved,
ADD COLUMN ml_model_confidence DECIMAL(4,3) AFTER ml_model_name,
ADD COLUMN false_positive_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER ml_model_confidence,
ADD COLUMN true_positive_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER false_positive_count;

CREATE INDEX idx_soc_attack_type ON soc_alerts (tenant_id, attack_type, created_at);
CREATE INDEX idx_soc_ioc ON soc_alerts (tenant_id, primary_ioc_type, primary_ioc_value(255));
CREATE INDEX idx_soc_ml_confidence ON soc_alerts (tenant_id, ml_model_confidence DESC, created_at);

-- ============================================================================
-- ENHANCE OTP_ATTEMPTS
-- ============================================================================
ALTER TABLE otp_attempts
ADD COLUMN delivery_latency_ms INT UNSIGNED AFTER channel,
ADD COLUMN provider_response_json JSON AFTER delivery_latency_ms,
ADD COLUMN attempt_number INT UNSIGNED AFTER provider_response_json,
ADD COLUMN total_attempts_for_purpose INT UNSIGNED AFTER attempt_number,
ADD COLUMN geo_country VARCHAR(2) AFTER total_attempts_for_purpose,
ADD COLUMN device_fingerprint VARCHAR(64) AFTER geo_country,
ADD COLUMN user_agent VARCHAR(512) AFTER device_fingerprint,
ADD COLUMN blocked TINYINT(1) NOT NULL DEFAULT 0 AFTER user_agent,
ADD COLUMN block_reason VARCHAR(128) AFTER blocked;

CREATE INDEX idx_otp_user_purpose_time ON otp_attempts (tenant_id, user_id, purpose, created_at);
CREATE INDEX idx_otp_blocked ON otp_attempts (tenant_id, blocked, created_at);
CREATE INDEX idx_otp_attempt_number ON otp_attempts (user_id, purpose, attempt_number);

-- ============================================================================
-- ENHANCE GLOBAL_PRINCIPALS
-- ============================================================================
ALTER TABLE global_principals
ADD COLUMN risk_score DECIMAL(4,3) AFTER risk_state,
ADD COLUMN risk_factors_json JSON AFTER risk_score,
ADD COLUMN last_risk_evaluated_at DATETIME(3) AFTER risk_factors_json,
ADD COLUMN identity_verified TINYINT(1) NOT NULL DEFAULT 0 AFTER last_risk_evaluated_at,
ADD COLUMN identity_verified_at DATETIME(3) AFTER identity_verified,
ADD COLUMN identity_verification_method ENUM('email','sms','webauthn','document','manual','oauth') AFTER identity_verified_at,
ADD COLUMN trusted_devices_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER identity_verification_method,
ADD COLUMN last_trusted_device_at DATETIME(3) AFTER trusted_devices_count,
ADD COLUMN account_age_days INT UNSIGNED AFTER last_trusted_device_at,
ADD COLUMN login_streak_days INT UNSIGNED NOT NULL DEFAULT 0 AFTER account_age_days,
ADD COLUMN longest_login_streak_days INT UNSIGNED NOT NULL DEFAULT 0 AFTER login_streak_days;

CREATE INDEX idx_principal_risk ON global_principals (risk_score DESC, created_at);
CREATE INDEX idx_principal_verified ON global_principals (identity_verified, created_at);

-- ============================================================================
-- ENHANCE TENANTS
-- ============================================================================
ALTER TABLE tenants
ADD COLUMN last_activity_at DATETIME(3) AFTER updated_at,
ADD COLUMN active_users_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER last_activity_at,
ADD COLUMN total_api_calls BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER active_users_count,
ADD COLUMN api_calls_reset_at DATETIME(3) AFTER total_api_calls,
ADD COLUMN storage_used_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER api_calls_reset_at,
ADD COLUMN storage_limit_bytes BIGINT UNSIGNED AFTER storage_used_bytes,
ADD COLUMN feature_flags_json JSON AFTER storage_limit_bytes,
ADD COLUMN health_score DECIMAL(4,3) AFTER feature_flags_json,
ADD COLUMN health_issues_json JSON AFTER health_score,
ADD COLUMN trial_end_at DATETIME(3) AFTER health_issues_json,
ADD COLUMN subscription_status ENUM('active','past_due','cancelled','trialing','paused') AFTER trial_end_at;

CREATE INDEX idx_tenant_health ON tenants (health_score, created_at);
CREATE INDEX idx_tenant_activity ON tenants (last_activity_at);
CREATE INDEX idx_tenant_subscription ON tenants (subscription_status, plan);

-- ============================================================================
-- ENHANCE DEVICES
-- ============================================================================
ALTER TABLE devices
ADD COLUMN trust_score DECIMAL(3,2) AFTER last_geo_country,
ADD COLUMN is_managed TINYINT(1) NOT NULL DEFAULT 0 AFTER trust_score,
ADD COLUMN managed_by_id BINARY(16) AFTER is_managed,
ADD COLUMN security_keys_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER managed_by_id,
ADD COLUMN last_security_key_at DATETIME(3) AFTER security_keys_count,
ADD COLUMN is_rooted TINYINT(1) NOT NULL DEFAULT 0 AFTER last_security_key_at,
ADD COLUMN is_emulator TINYINT(1) NOT NULL DEFAULT 0 AFTER is_rooted,
ADD COLUMN screen_lock_enabled TINYINT(1) AFTER is_emulator,
ADD COLUMN encryption_enabled TINYINT(1) AFTER screen_lock_enabled,
ADD COLUMN last_security_scan_at DATETIME(3) AFTER encryption_enabled,
ADD COLUMN security_scan_result VARCHAR(64) AFTER last_security_scan_at;

CREATE INDEX idx_devices_trust ON devices (trust_score, last_login_at);
CREATE INDEX idx_devices_security ON devices (tenant_id, is_rooted, is_emulator, created_at);

-- ============================================================================
-- INSERT DEFAULT SCHEMA VERSION
-- ============================================================================
-- INSERT INTO schema_versions (version, description, checksum, applied_at, applied_by, duration_ms)
-- VALUES (
--   30,
--   'Add Meta Engineer telemetry: security events, API metrics, tenant analytics, threat intel, behavior tracking',
--   SHA2('V030__meta_engineer_telemetry', 256),
--   NOW(3),
--   'system',
--   0
-- );
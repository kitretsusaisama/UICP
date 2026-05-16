-- V027: OTP Isolation Tables for Zero-Trust Multi-Tenant Architecture
-- This migration adds comprehensive tenant isolation for OTP operations

-- ============================================================================
-- TENANT OTP WIDGET CONFIG - Isolated widget configuration per tenant
-- ============================================================================
CREATE TABLE tenant_otp_widget_configs (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,

  -- Provider configuration (tenant-specific)
  provider_name VARCHAR(64) NOT NULL DEFAULT 'MSG91',
  widget_id VARCHAR(128) NOT NULL,
  token_auth_encrypted VARCHAR(512) NOT NULL,

  -- Theme configuration (tenant-specific)
  theme_config JSON NOT NULL,
  layout_config JSON NOT NULL,
  behavior_config JSON NOT NULL,

  -- Localization (tenant-specific)
  localization JSON NOT NULL,

  -- Security (tenant-specific)
  allowed_origins JSON NOT NULL,
  allowed_channels JSON NOT NULL,
  ip_whitelist JSON,

  -- Isolation verification
  isolation_verified_at DATETIME(3),
  isolation_signature VARCHAR(256),

  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,

  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_widget (tenant_id),
  KEY idx_tenant_widget_provider (tenant_id, provider_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TENANT OTP RISK POLICIES - Per-tenant risk configuration
-- ============================================================================
CREATE TABLE tenant_otp_risk_policies (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,

  -- Velocity limits (tenant-specific)
  max_attempts_per_hour INT NOT NULL DEFAULT 10,
  max_attempts_per_day INT NOT NULL DEFAULT 50,
  max_attempts_per_identity INT NOT NULL DEFAULT 5,

  -- Geographic rules (tenant-specific)
  allowed_countries JSON,
  blocked_countries JSON,
  block_unknown_geo TINYINT(1) NOT NULL DEFAULT 0,

  -- Device rules (tenant-specific)
  require_device_fingerprint TINYINT(1) NOT NULL DEFAULT 0,
  block_unknown_devices TINYINT(1) NOT NULL DEFAULT 0,
  max_devices_per_identity INT NOT NULL DEFAULT 10,

  -- Provider rules (tenant-specific)
  trusted_providers JSON,
  require_provider_verification TINYINT(1) NOT NULL DEFAULT 1,

  -- Risk thresholds (tenant-specific)
  risk_threshold_low INT NOT NULL DEFAULT 30,
  risk_threshold_high INT NOT NULL DEFAULT 70,
  block_on_high_risk TINYINT(1) NOT NULL DEFAULT 1,

  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,

  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_risk_policy (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TENANT ADAPTIVE MODELS - Per-tenant ML model data
-- ============================================================================
CREATE TABLE tenant_otp_adaptive_models (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,

  -- Model data (JSON serialized)
  channel_success_rates JSON NOT NULL,
  provider_success_rates JSON NOT NULL,
  hourly_patterns JSON NOT NULL,
  user_segment_patterns JSON NOT NULL,

  -- Model metadata
  model_version INT NOT NULL DEFAULT 1,
  last_trained_at DATETIME(3),
  training_data_points INT NOT NULL DEFAULT 0,

  -- Status
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,

  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_adaptive_model (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- OTP DELIVERY TELEMETRY - Per-tenant, per-operation tracking
-- ============================================================================
CREATE TABLE otp_delivery_telemetry (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,

  -- Operation details
  operation_type ENUM('SEND', 'VERIFY', 'RETRY', 'REPLAY') NOT NULL,
  channel ENUM('SMS', 'WHATSAPP', 'VOICE', 'EMAIL') NOT NULL,
  provider_name VARCHAR(64) NOT NULL,

  -- Identity
  identity_hash VARCHAR(64) NOT NULL,

  -- Outcome
  success TINYINT(1) NOT NULL,
  failure_reason VARCHAR(256),
  latency_ms INT,

  -- Context
  device_fingerprint VARCHAR(128),
  ip_address VARCHAR(45),
  geo_country VARCHAR(2),
  user_agent VARCHAR(512),

  -- Timing
  created_at DATETIME(3) NOT NULL,

  PRIMARY KEY (id),
  KEY idx_telemetry_tenant_time (tenant_id, created_at),
  KEY idx_telemetry_tenant_identity (tenant_id, identity_hash, created_at),
  KEY idx_telemetry_tenant_provider (tenant_id, provider_name, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- ENHANCE EXISTING TENANT SMS PROVIDERS - Add isolation fields
-- ============================================================================
ALTER TABLE tenant_sms_providers
ADD COLUMN tenant_isolation_key VARCHAR(64) GENERATED ALWAYS AS (
  CONCAT(HEX(tenant_id), ':', provider_name)
) STORED,
ADD COLUMN circuit_state ENUM('CLOSED', 'OPEN', 'HALF_OPEN') NOT NULL DEFAULT 'CLOSED',
ADD COLUMN circuit_failure_count INT NOT NULL DEFAULT 0,
ADD COLUMN circuit_success_count INT NOT NULL DEFAULT 0,
ADD COLUMN circuit_last_failure_at DATETIME(3),
ADD COLUMN circuit_last_success_at DATETIME(3),
ADD COLUMN circuit_reset_at DATETIME(3),
ADD COLUMN tenant_rate_limit_per_min INT NOT NULL DEFAULT 60,
ADD COLUMN tenant_daily_limit INT NOT NULL DEFAULT 1000,
ADD COLUMN fallback_chain JSON;

-- Add unique constraint for tenant isolation
ALTER TABLE tenant_sms_providers ADD UNIQUE INDEX uq_tenant_provider_isolation (tenant_id, provider_name);

-- ============================================================================
-- OTP CHALLENGES WITH TENANT ISOLATION - Enhanced challenges table
-- ============================================================================
ALTER TABLE otp_flows
ADD COLUMN tenant_isolation_key VARCHAR(64) GENERATED ALWAYS AS (
  CONCAT(HEX(tenant_id), ':', HEX(id))
) STORED,
ADD COLUMN lineage_id BINARY(16),
ADD COLUMN device_fingerprint VARCHAR(128),
ADD COLUMN ip_address VARCHAR(45),
ADD COLUMN risk_score INT,
ADD COLUMN risk_level ENUM('LOW', 'MEDIUM', 'HIGH'),
ADD COLUMN provider_verified TINYINT(1),
ADD COLUMN verification_details JSON;

ALTER TABLE otp_flows ADD INDEX idx_otp_flows_tenant_lineage (tenant_id, lineage_id);
ALTER TABLE otp_flows ADD INDEX idx_otp_flows_tenant_risk (tenant_id, risk_level);

-- ============================================================================
-- AUDIT LOG FOR TENANT ISOLATION VERIFICATION
-- ============================================================================
CREATE TABLE otp_isolation_audit (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,

  -- Operation
  operation ENUM('VALIDATE_ACCESS', 'CHECK_PROVIDER', 'VERIFY_CONFIG', 'CHECK_RATE_LIMIT') NOT NULL,
  resource_type VARCHAR(64),
  resource_id BINARY(16),

  -- Result
  allowed TINYINT(1) NOT NULL,
  isolation_level ENUM('VERIFIED', 'FAILED', 'BYPASSED') NOT NULL,
  failure_reason VARCHAR(256),

  -- Context
  requesting_principal VARCHAR(128),
  ip_address VARCHAR(45),

  created_at DATETIME(3) NOT NULL,

  PRIMARY KEY (id),
  KEY idx_isolation_audit_tenant_time (tenant_id, created_at),
  KEY idx_isolation_audit_operation (tenant_id, operation, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
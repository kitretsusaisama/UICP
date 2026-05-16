CREATE TABLE tenant_sms_providers (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  provider_name VARCHAR(64) NOT NULL,
  provider_type VARCHAR(64) NOT NULL,
  credentials_ref VARCHAR(255) NOT NULL,
  sender_id VARCHAR(64),
  template_id VARCHAR(128),
  region VARCHAR(32),
  priority INT NOT NULL DEFAULT 100,
  is_primary TINYINT(1) NOT NULL DEFAULT 0,
  is_enabled TINYINT(1) NOT NULL DEFAULT 1,
  fallback_provider_id BINARY(16),
  rate_limit_per_min INT NOT NULL DEFAULT 60,
  daily_limit INT NOT NULL DEFAULT 1000,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  KEY idx_tenant_sms_provider (tenant_id, provider_name, is_enabled, priority)
);

CREATE TABLE tenant_email_providers (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  provider_name VARCHAR(64) NOT NULL,
  provider_type VARCHAR(64) NOT NULL,
  credentials_ref VARCHAR(255) NOT NULL,
  from_email VARCHAR(320) NOT NULL,
  from_name VARCHAR(160),
  reply_to VARCHAR(320),
  domain VARCHAR(255),
  region VARCHAR(32),
  priority INT NOT NULL DEFAULT 100,
  is_primary TINYINT(1) NOT NULL DEFAULT 0,
  is_enabled TINYINT(1) NOT NULL DEFAULT 1,
  fallback_provider_id BINARY(16),
  rate_limit_per_min INT NOT NULL DEFAULT 120,
  daily_limit INT NOT NULL DEFAULT 10000,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  KEY idx_tenant_email_provider (tenant_id, provider_name, is_enabled, priority)
);

CREATE TABLE communication_templates (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  channel ENUM('SMS','EMAIL','WHATSAPP','VOICE') NOT NULL,
  template_key VARCHAR(128) NOT NULL,
  provider_template_id VARCHAR(128),
  subject VARCHAR(255),
  html_template MEDIUMTEXT,
  text_template MEDIUMTEXT,
  sms_template VARCHAR(1024),
  locale VARCHAR(16) NOT NULL DEFAULT 'en',
  version INT NOT NULL DEFAULT 1,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_comm_template (tenant_id, channel, template_key, locale, version)
);

CREATE TABLE otp_flows (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  principal_id BINARY(16),
  identity VARCHAR(320) NOT NULL,
  channel ENUM('SMS','EMAIL','WHATSAPP','VOICE') NOT NULL,
  purpose VARCHAR(64) NOT NULL,
  provider_name VARCHAR(64),
  provider_request_id VARCHAR(128),
  status ENUM('created','queued','sent','verified','expired','failed','replayed') NOT NULL DEFAULT 'created',
  attempt_count INT NOT NULL DEFAULT 0,
  resend_count INT NOT NULL DEFAULT 0,
  verified_at DATETIME(3),
  expires_at DATETIME(3) NOT NULL,
  created_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  KEY idx_otp_flow_tenant_identity (tenant_id, identity, purpose, status)
);

CREATE TABLE communication_delivery_attempts (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  flow_id BINARY(16),
  channel ENUM('SMS','EMAIL','WHATSAPP','VOICE') NOT NULL,
  provider_name VARCHAR(64) NOT NULL,
  provider_message_id VARCHAR(128),
  status ENUM('queued','sent','delivered','failed','bounced','complained','duplicate') NOT NULL,
  error_code VARCHAR(64),
  error_message VARCHAR(1024),
  latency_ms INT,
  retry_count INT NOT NULL DEFAULT 0,
  idempotency_key VARCHAR(255) NOT NULL,
  created_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_delivery_idempotency (tenant_id, idempotency_key),
  KEY idx_delivery_lineage (tenant_id, flow_id, provider_name)
);

CREATE TABLE provider_health (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  provider_name VARCHAR(64) NOT NULL,
  channel ENUM('SMS','EMAIL','WHATSAPP','VOICE') NOT NULL,
  success_rate DECIMAL(5,2) NOT NULL DEFAULT 100.00,
  failure_rate DECIMAL(5,2) NOT NULL DEFAULT 0.00,
  p95_latency_ms INT NOT NULL DEFAULT 0,
  last_success_at DATETIME(3),
  last_failure_at DATETIME(3),
  circuit_state ENUM('CLOSED','OPEN','HALF_OPEN') NOT NULL DEFAULT 'CLOSED',
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_provider_health (tenant_id, provider_name, channel)
);

CREATE TABLE provider_webhook_events (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16),
  provider_name VARCHAR(64) NOT NULL,
  event_id VARCHAR(255) NOT NULL,
  event_type VARCHAR(128) NOT NULL,
  payload_json JSON NOT NULL,
  processed_at DATETIME(3),
  created_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_provider_webhook_event (provider_name, event_id)
);

CREATE TABLE communication_idempotency_keys (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  scope VARCHAR(64) NOT NULL,
  key_hash CHAR(64) NOT NULL,
  resource_id BINARY(16),
  expires_at DATETIME(3) NOT NULL,
  created_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_comm_idempotency (tenant_id, scope, key_hash)
);

CREATE TABLE tenant_provider_rate_limits (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  provider_name VARCHAR(64) NOT NULL,
  channel ENUM('SMS','EMAIL','WHATSAPP','VOICE') NOT NULL,
  limit_per_min INT NOT NULL,
  burst INT NOT NULL,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_provider_rate_limit (tenant_id, provider_name, channel)
);

CREATE TABLE tenant_provider_quotas (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  provider_name VARCHAR(64) NOT NULL,
  channel ENUM('SMS','EMAIL','WHATSAPP','VOICE') NOT NULL,
  daily_limit INT NOT NULL,
  monthly_limit INT,
  hard_block_at_limit TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_provider_quota (tenant_id, provider_name, channel)
);

CREATE TABLE tenant_verified_sender_domains (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  domain VARCHAR(255) NOT NULL,
  provider_name VARCHAR(64) NOT NULL,
  verification_status ENUM('pending','verified','failed') NOT NULL DEFAULT 'pending',
  dkim_status ENUM('pending','verified','failed') NOT NULL DEFAULT 'pending',
  spf_status ENUM('pending','verified','failed') NOT NULL DEFAULT 'pending',
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sender_domain (tenant_id, domain, provider_name)
);

CREATE TABLE tenant_sender_ids (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  provider_name VARCHAR(64) NOT NULL,
  sender_id VARCHAR(64) NOT NULL,
  verification_status ENUM('pending','verified','failed') NOT NULL DEFAULT 'pending',
  created_at DATETIME(3) NOT NULL,
  updated_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sender_id (tenant_id, provider_name, sender_id)
);

CREATE TABLE provider_circuit_events (
  id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  provider_name VARCHAR(64) NOT NULL,
  channel ENUM('SMS','EMAIL','WHATSAPP','VOICE') NOT NULL,
  from_state ENUM('CLOSED','OPEN','HALF_OPEN'),
  to_state ENUM('CLOSED','OPEN','HALF_OPEN') NOT NULL,
  reason VARCHAR(255),
  created_at DATETIME(3) NOT NULL,
  PRIMARY KEY (id),
  KEY idx_circuit_events (tenant_id, provider_name, channel, created_at)
);

-- UICP Multi-Tenant Email Communication Tables
-- V028__create_email_tables.sql

-- Global provider registry (system-wide available providers)
CREATE TABLE email_providers (
  id BINARY(16) PRIMARY KEY,
  provider_key VARCHAR(32) NOT NULL UNIQUE,
  provider_type VARCHAR(32) NOT NULL,
  display_name VARCHAR(64) NOT NULL,
  website_url VARCHAR(256),
  capabilities JSON NOT NULL,
  default_rate_limit_per_min INT NOT NULL DEFAULT 60,
  default_daily_limit INT NOT NULL DEFAULT 10000,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  INDEX idx_active (is_active)
);

-- Per-tenant provider configuration
CREATE TABLE tenant_email_providers (
  id BINARY(16) PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  provider_key VARCHAR(32) NOT NULL,
  provider_name VARCHAR(32) NOT NULL,
  -- Credentials (encrypted at rest)
  api_key_encrypted VARCHAR(1024),
  api_secret_encrypted VARCHAR(1024),
  access_key_encrypted VARCHAR(1024),
  secret_key_encrypted VARCHAR(1024),
  smtp_host VARCHAR(256),
  smtp_port INT DEFAULT 587,
  smtp_username VARCHAR(256),
  smtp_password_encrypted VARCHAR(1024),
  smtp_tls BOOLEAN DEFAULT TRUE,
  -- Sender configuration
  from_email VARCHAR(128) NOT NULL,
  from_name VARCHAR(64),
  reply_to VARCHAR(128),
  domain VARCHAR(128),
  region VARCHAR(32),
  -- Routing configuration
  priority INT NOT NULL DEFAULT 1,
  is_primary BOOLEAN NOT NULL DEFAULT FALSE,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  weight INT NOT NULL DEFAULT 100,
  -- Rate limits
  rate_limit_per_min INT NOT NULL DEFAULT 60,
  daily_limit INT NOT NULL DEFAULT 10000,
  monthly_limit INT,
  -- Circuit breaker state
  circuit_state ENUM('CLOSED', 'OPEN', 'HALF_OPEN') DEFAULT 'CLOSED',
  circuit_failure_count INT DEFAULT 0,
  circuit_success_count INT DEFAULT 0,
  circuit_last_failure_at DATETIME(3),
  circuit_last_success_at DATETIME(3),
  circuit_reset_at DATETIME(3),
  -- Health metrics (24h rolling)
  success_count_24h INT DEFAULT 0,
  failure_count_24h INT DEFAULT 0,
  avg_latency_ms INT,
  last_health_check_at DATETIME(3),
  -- Metadata
  custom_settings JSON,
  tags JSON,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_tenant_provider (tenant_id, provider_key),
  INDEX idx_tenant_primary (tenant_id, is_primary),
  INDEX idx_tenant_enabled (tenant_id, is_enabled),
  INDEX idx_circuit_state (tenant_id, provider_key, circuit_state),
  INDEX idx_tenant_id (tenant_id)
);

-- Tenant-scoped email templates
CREATE TABLE email_templates (
  id BINARY(16) PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  template_key VARCHAR(64) NOT NULL,
  provider_template_id VARCHAR(128),
  subject_template VARCHAR(256) NOT NULL,
  html_template TEXT NOT NULL,
  text_template TEXT,
  locale VARCHAR(8) DEFAULT 'en',
  version INT NOT NULL DEFAULT 1,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_tenant_template_locale (tenant_id, template_key, locale),
  INDEX idx_tenant_active (tenant_id, is_active),
  INDEX idx_tenant_id (tenant_id)
);

-- Email delivery logs
CREATE TABLE email_logs (
  id BINARY(16) PRIMARY KEY,
  tenant_id BINARY(16) NOT NULL,
  lineage_id VARCHAR(64) NOT NULL,
  provider_name VARCHAR(32) NOT NULL,
  message_id VARCHAR(128),
  provider_message_id VARCHAR(128),
  recipient VARCHAR(256) NOT NULL,
  subject VARCHAR(256),
  template_key VARCHAR(64),
  status ENUM('QUEUED', 'SENT', 'DELIVERED', 'BOUNCED', 'FAILED', 'RETRYING') NOT NULL,
  error_message TEXT,
  retry_count INT NOT NULL DEFAULT 0,
  provider_latency_ms INT,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  delivered_at DATETIME(3),
  INDEX idx_tenant_status (tenant_id, status),
  INDEX idx_lineage (lineage_id),
  INDEX idx_provider_message (provider_message_id),
  INDEX idx_tenant_id (tenant_id),
  INDEX idx_created_at (created_at)
);

-- Email provider health (aggregated metrics)
CREATE TABLE email_provider_health (
  id BINARY(16) PRIMARY KEY,
  provider_name VARCHAR(32) NOT NULL,
  tenant_id BINARY(16),
  success_count INT NOT NULL DEFAULT 0,
  failure_count INT NOT NULL DEFAULT 0,
  last_failure_at DATETIME(3),
  last_success_at DATETIME(3),
  circuit_state ENUM('CLOSED', 'OPEN', 'HALF_OPEN') DEFAULT 'CLOSED',
  avg_latency_ms INT,
  p95_latency_ms INT,
  success_rate DECIMAL(5, 4) DEFAULT 1.0000,
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_provider_tenant (provider_name, tenant_id),
  INDEX idx_provider_name (provider_name),
  INDEX idx_tenant_id (tenant_id)
);

-- Insert default provider registry entries
INSERT INTO email_providers (id, provider_key, provider_type, display_name, website_url, capabilities) VALUES
(UUID_TO_BIN(UUID()), 'RESEND', 'RESEND', 'Resend', 'https://resend.com', JSON_OBJECT('supportsWebhooks', true, 'supportsTemplates', true, 'supportsBatch', true, 'supportsCustomHeaders', true, 'maxRecipientsPerSend', 100, 'regions', JSON_ARRAY('us-east-1', 'eu-west-1', 'ap-south-1'))),
(UUID_TO_BIN(UUID()), 'MAILEROO', 'MAILEROO', 'Maileroo', 'https://maileroo.com', JSON_OBJECT('supportsWebhooks', true, 'supportsTemplates', false, 'supportsBatch', true, 'supportsCustomHeaders', true, 'maxRecipientsPerSend', 50, 'regions', JSON_ARRAY('us-east-1', 'eu-west-1'))),
(UUID_TO_BIN(UUID()), 'AWS_SES', 'AWS_SES', 'AWS SES', 'https://aws.amazon.com/ses/', JSON_OBJECT('supportsWebhooks', true, 'supportsTemplates', false, 'supportsBatch', true, 'supportsCustomHeaders', true, 'maxRecipientsPerSend', 50, 'regions', JSON_ARRAY('us-east-1', 'us-west-2', 'eu-west-1'))),
(UUID_TO_BIN(UUID()), 'SENDGRID', 'SENDGRID', 'SendGrid', 'https://sendgrid.com', JSON_OBJECT('supportsWebhooks', true, 'supportsTemplates', true, 'supportsBatch', true, 'supportsCustomHeaders', true, 'maxRecipientsPerSend', 1000, 'regions', JSON_ARRAY('us-east-1', 'eu-west-1'))),
(UUID_TO_BIN(UUID()), 'POSTMARK', 'POSTMARK', 'Postmark', 'https://postmarkapp.com', JSON_OBJECT('supportsWebhooks', true, 'supportsTemplates', true, 'supportsBatch', true, 'supportsCustomHeaders', true, 'maxRecipientsPerSend', 50, 'regions', JSON_ARRAY('us-east-1', 'eu-west-1'))),
(UUID_TO_BIN(UUID()), 'MAILGUN', 'MAILGUN', 'Mailgun', 'https://mailgun.com', JSON_OBJECT('supportsWebhooks', true, 'supportsTemplates', false, 'supportsBatch', true, 'supportsCustomHeaders', true, 'maxRecipientsPerSend', 1000, 'regions', JSON_ARRAY('us-east-1', 'eu-west-1'))),
(UUID_TO_BIN(UUID()), 'SMTP', 'SMTP', 'Custom SMTP', NULL, JSON_OBJECT('supportsWebhooks', false, 'supportsTemplates', false, 'supportsBatch', true, 'supportsCustomHeaders', true, 'maxRecipientsPerSend', 50, 'regions', JSON_ARRAY()));
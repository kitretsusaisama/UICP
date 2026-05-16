-- V034: Platform Services Additional Tables
-- Platform Approval, Security, Data Governance, Config, Audit, Resilience, Region tables

-- Platform Approval Requests
CREATE TABLE IF NOT EXISTS platform_approval_requests (
  id VARCHAR(26) PRIMARY KEY,
  requester_id VARCHAR(26) NOT NULL,
  requester_tenant_id VARCHAR(26),
  resource_type VARCHAR(100) NOT NULL,
  resource_id VARCHAR(26),
  action VARCHAR(100) NOT NULL,
  justification TEXT,
  status ENUM('pending', 'approved', 'rejected', 'escalated', 'expired') DEFAULT 'pending',
  priority ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
  requested_at DATETIME NOT NULL,
  expires_at DATETIME NOT NULL,
  approved_by VARCHAR(26),
  approved_at DATETIME,
  rejected_by VARCHAR(26),
  rejected_at DATETIME,
  escalation_level INT DEFAULT 0,
  approvers JSON,
  metadata JSON,
  INDEX idx_requester (requester_id),
  INDEX idx_tenant (requester_tenant_id),
  INDEX idx_status (status),
  INDEX idx_requested (requested_at)
);

-- Security Incidents
CREATE TABLE IF NOT EXISTS security_incidents (
  id VARCHAR(26) PRIMARY KEY,
  tenant_id VARCHAR(26),
  severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
  type VARCHAR(100) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  status ENUM('open', 'investigating', 'contained', 'resolved', 'closed') DEFAULT 'open',
  source VARCHAR(100),
  ip_address VARCHAR(45),
  user_agent VARCHAR(500),
  affected_resources JSON,
  indicators JSON,
  mitigation TEXT,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  resolved_at DATETIME,
  resolved_by VARCHAR(26),
  INDEX idx_tenant (tenant_id),
  INDEX idx_status (status),
  INDEX idx_severity (severity),
  INDEX idx_created (created_at)
);

-- Threat Intelligence
CREATE TABLE IF NOT EXISTS threat_intelligence (
  id VARCHAR(26) PRIMARY KEY,
  indicator VARCHAR(500) NOT NULL,
  type ENUM('ip', 'domain', 'hash', 'url') NOT NULL,
  threat_level ENUM('low', 'medium', 'high', 'critical') NOT NULL,
  source VARCHAR(100) NOT NULL,
  description TEXT,
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  tags JSON,
  metadata JSON,
  UNIQUE KEY uk_indicator_type (indicator, type),
  INDEX idx_threat_level (threat_level),
  INDEX idx_last_seen (last_seen)
);

-- Vulnerability Scans
CREATE TABLE IF NOT EXISTS vulnerability_scans (
  id VARCHAR(26) PRIMARY KEY,
  tenant_id VARCHAR(26) NOT NULL,
  status ENUM('running', 'completed', 'failed') DEFAULT 'running',
  started_at DATETIME NOT NULL,
  completed_at DATETIME,
  results JSON,
  INDEX idx_tenant (tenant_id),
  INDEX idx_status (status)
);

-- Consents
CREATE TABLE IF NOT EXISTS consents (
  id VARCHAR(26) PRIMARY KEY,
  identity_id VARCHAR(26) NOT NULL,
  tenant_id VARCHAR(26) NOT NULL,
  consent_type VARCHAR(100) NOT NULL,
  granted BOOLEAN NOT NULL DEFAULT TRUE,
  purpose VARCHAR(255),
  version VARCHAR(50),
  source VARCHAR(100),
  granted_at DATETIME NOT NULL,
  withdrawn_at DATETIME,
  metadata JSON,
  INDEX idx_identity (identity_id),
  INDEX idx_tenant (tenant_id),
  INDEX idx_type (consent_type),
  INDEX idx_granted (granted)
);

-- Retention Policies
CREATE TABLE IF NOT EXISTS retention_policies (
  id VARCHAR(26) PRIMARY KEY,
  tenant_id VARCHAR(26) NOT NULL,
  name VARCHAR(255) NOT NULL,
  data_type VARCHAR(100) NOT NULL,
  retention_days INT NOT NULL,
  action ENUM('delete', 'archive', 'anonymize') NOT NULL,
  conditions JSON,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  created_by VARCHAR(26),
  INDEX idx_tenant (tenant_id),
  INDEX idx_data_type (data_type)
);

-- Retention Purges
CREATE TABLE IF NOT EXISTS retention_purges (
  id VARCHAR(26) PRIMARY KEY,
  tenant_id VARCHAR(26) NOT NULL,
  policy_id VARCHAR(26),
  status ENUM('running', 'completed', 'failed') DEFAULT 'running',
  triggered_at DATETIME NOT NULL,
  completed_at DATETIME,
  affected_records INT DEFAULT 0,
  INDEX idx_tenant (tenant_id),
  INDEX idx_status (status)
);

-- DSAR Requests
CREATE TABLE IF NOT EXISTS dsar_requests (
  id VARCHAR(26) PRIMARY KEY,
  requester_email VARCHAR(255) NOT NULL,
  tenant_id VARCHAR(26) NOT NULL,
  request_type ENUM('access', 'deletion', 'portability', 'correction') NOT NULL,
  status ENUM('pending', 'identity_verified', 'processing', 'completed', 'rejected', 'expired') DEFAULT 'pending',
  identity_verified BOOLEAN DEFAULT FALSE,
  verified_at DATETIME,
  data_categories JSON,
  requested_at DATETIME NOT NULL,
  expires_at DATETIME NOT NULL,
  completed_at DATETIME,
  completed_by VARCHAR(26),
  rejection_reason TEXT,
  metadata JSON,
  INDEX idx_tenant (tenant_id),
  INDEX idx_status (status),
  INDEX idx_requester (requester_email)
);

-- Platform Config
CREATE TABLE IF NOT EXISTS platform_config (
  id VARCHAR(26) PRIMARY KEY,
  `key` VARCHAR(255) NOT NULL,
  UNIQUE KEY uk_key (`key`),
  value TEXT NOT NULL,
  category VARCHAR(100) NOT NULL,
  description TEXT,
  is_encrypted BOOLEAN DEFAULT FALSE,
  is_public BOOLEAN DEFAULT FALSE,
  version INT DEFAULT 1,
  updated_at DATETIME NOT NULL,
  updated_by VARCHAR(26),
  INDEX idx_category (category),
  INDEX idx_public (is_public)
);

-- Platform Announcements
CREATE TABLE IF NOT EXISTS platform_announcements (
  id VARCHAR(26) PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  content TEXT NOT NULL,
  type ENUM('info', 'warning', 'critical', 'maintenance') NOT NULL,
  target_tenants JSON,
  starts_at DATETIME NOT NULL,
  ends_at DATETIME,
  created_by VARCHAR(26),
  created_at DATETIME NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  INDEX idx_active (is_active),
  INDEX idx_starts (starts_at)
);

-- Platform Audit Logs
CREATE TABLE IF NOT EXISTS platform_audit_logs (
  id VARCHAR(26) PRIMARY KEY,
  action VARCHAR(100) NOT NULL,
  resource_type VARCHAR(100) NOT NULL,
  resource_id VARCHAR(26),
  actor_id VARCHAR(26),
  actor_type VARCHAR(50),
  tenant_id VARCHAR(26),
  metadata JSON,
  ip_address VARCHAR(45),
  user_agent VARCHAR(500),
  created_at DATETIME NOT NULL,
  INDEX idx_action (action),
  INDEX idx_resource (resource_type, resource_id),
  INDEX idx_actor (actor_id),
  INDEX idx_tenant (tenant_id),
  INDEX idx_created (created_at)
);

-- Sign-in Logs
CREATE TABLE IF NOT EXISTS sign_in_logs (
  id VARCHAR(26) PRIMARY KEY,
  identity_id VARCHAR(26) NOT NULL,
  tenant_id VARCHAR(26),
  method VARCHAR(50) NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  user_agent VARCHAR(500),
  success BOOLEAN NOT NULL,
  failure_reason VARCHAR(255),
  mfa_used BOOLEAN DEFAULT FALSE,
  created_at DATETIME NOT NULL,
  INDEX idx_identity (identity_id),
  INDEX idx_tenant (tenant_id),
  INDEX idx_success (success),
  INDEX idx_created (created_at)
);

-- Audit Exports
CREATE TABLE IF NOT EXISTS audit_exports (
  id VARCHAR(26) PRIMARY KEY,
  tenant_id VARCHAR(26),
  start_date DATETIME NOT NULL,
  end_date DATETIME NOT NULL,
  format VARCHAR(20) NOT NULL,
  file_url VARCHAR(500),
  status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
  created_at DATETIME NOT NULL,
  INDEX idx_tenant (tenant_id),
  INDEX idx_status (status)
);

-- Compliance Reports
CREATE TABLE IF NOT EXISTS compliance_reports (
  id VARCHAR(26) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  type VARCHAR(100) NOT NULL,
  tenant_id VARCHAR(26),
  status ENUM('generating', 'ready', 'failed') DEFAULT 'generating',
  format VARCHAR(20) DEFAULT 'pdf',
  file_url VARCHAR(500),
  generated_by VARCHAR(26),
  generated_at DATETIME,
  expires_at DATETIME,
  INDEX idx_tenant (tenant_id),
  INDEX idx_status (status)
);

-- Health Checks
CREATE TABLE IF NOT EXISTS health_checks (
  id VARCHAR(26) PRIMARY KEY,
  status ENUM('healthy', 'degraded', 'unhealthy') NOT NULL,
  components JSON,
  uptime BIGINT,
  version VARCHAR(50),
  checked_at DATETIME NOT NULL,
  INDEX idx_status (status),
  INDEX idx_checked (checked_at)
);

-- Resilience Incidents
CREATE TABLE IF NOT EXISTS resilience_incidents (
  id VARCHAR(26) PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
  status ENUM('open', 'investigating', 'identified', 'monitoring', 'resolved') DEFAULT 'open',
  components JSON,
  started_at DATETIME NOT NULL,
  resolved_at DATETIME,
  updates JSON,
  created_by VARCHAR(26),
  INDEX idx_status (status),
  INDEX idx_severity (severity),
  INDEX idx_started (started_at)
);

-- Circuit Breakers
CREATE TABLE IF NOT EXISTS circuit_breakers (
  id VARCHAR(26) PRIMARY KEY,
  service VARCHAR(100) NOT NULL,
  UNIQUE KEY uk_service (service),
  state ENUM('closed', 'open', 'half_open') DEFAULT 'closed',
  failure_count INT DEFAULT 0,
  last_failure_at DATETIME,
  threshold INT DEFAULT 5,
  timeout INT DEFAULT 30,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  INDEX idx_service (service),
  INDEX idx_state (state)
);

-- Chaos Experiments
CREATE TABLE IF NOT EXISTS chaos_experiments (
  id VARCHAR(26) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  type VARCHAR(100) NOT NULL,
  status ENUM('pending', 'running', 'completed', 'failed', 'cancelled') DEFAULT 'pending',
  target_services JSON,
  parameters JSON,
  created_by VARCHAR(26),
  started_at DATETIME,
  completed_at DATETIME,
  INDEX idx_status (status),
  INDEX idx_type (type)
);

-- Regions
CREATE TABLE IF NOT EXISTS regions (
  id VARCHAR(26) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  code VARCHAR(10) NOT NULL,
  UNIQUE KEY uk_code (code),
  location VARCHAR(255) NOT NULL,
  status ENUM('active', 'inactive', 'maintenance') DEFAULT 'active',
  primary_endpoint VARCHAR(500),
  is_primary BOOLEAN DEFAULT FALSE,
  capacity INT DEFAULT 1000,
  current_load INT DEFAULT 0,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  INDEX idx_code (code),
  INDEX idx_status (status),
  INDEX idx_primary (is_primary)
);

-- Geo Routing Rules
CREATE TABLE IF NOT EXISTS geo_routing_rules (
  id VARCHAR(26) PRIMARY KEY,
  country_codes JSON NOT NULL,
  region_code VARCHAR(10) NOT NULL,
  priority INT DEFAULT 0,
  is_active BOOLEAN DEFAULT TRUE,
  created_at DATETIME NOT NULL,
  INDEX idx_region (region_code),
  INDEX idx_active (is_active)
);

-- Failover Records
CREATE TABLE IF NOT EXISTS failover_records (
  id VARCHAR(26) PRIMARY KEY,
  region_id VARCHAR(26) NOT NULL,
  target_region_id VARCHAR(26) NOT NULL,
  type ENUM('manual', 'automatic') NOT NULL,
  status ENUM('pending', 'in_progress', 'completed', 'failed') DEFAULT 'pending',
  triggered_by VARCHAR(26),
  triggered_at DATETIME NOT NULL,
  completed_at DATETIME,
  metadata JSON,
  INDEX idx_region (region_id),
  INDEX idx_status (status)
);

-- Tenant Settings
CREATE TABLE IF NOT EXISTS tenant_settings (
  tenant_id VARCHAR(26) PRIMARY KEY,
  impersonation_requires_approval BOOLEAN DEFAULT TRUE,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

-- Tenant Migrations
CREATE TABLE IF NOT EXISTS tenant_migrations (
  id VARCHAR(26) PRIMARY KEY,
  tenant_id VARCHAR(26) NOT NULL,
  target_region VARCHAR(50) NOT NULL,
  status ENUM('pending', 'in_progress', 'completed', 'failed') DEFAULT 'pending',
  created_at DATETIME NOT NULL,
  completed_at DATETIME,
  INDEX idx_tenant (tenant_id),
  INDEX idx_status (status)
);

-- Tenant Usage Metrics
CREATE TABLE IF NOT EXISTS tenant_usage_metrics (
  id VARCHAR(26) PRIMARY KEY,
  tenant_id VARCHAR(26) NOT NULL,
  api_calls INT DEFAULT 0,
  storage_mb BIGINT DEFAULT 0,
  user_id VARCHAR(26),
  domain_id VARCHAR(26),
  period DATE NOT NULL,
  INDEX idx_tenant_period (tenant_id, period)
);

-- Security Anomalies
CREATE TABLE IF NOT EXISTS security_anomalies (
  id VARCHAR(26) PRIMARY KEY,
  tenant_id VARCHAR(26),
  anomaly_type VARCHAR(100) NOT NULL,
  description TEXT,
  severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
  detected_at DATETIME NOT NULL,
  metadata JSON,
  INDEX idx_tenant (tenant_id),
  INDEX idx_detected (detected_at)
);
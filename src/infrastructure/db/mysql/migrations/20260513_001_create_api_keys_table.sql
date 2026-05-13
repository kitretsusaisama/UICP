-- Migration: Create api_keys table
-- Date: 2026-05-13

CREATE TABLE IF NOT EXISTS api_keys (
  id VARCHAR(26) PRIMARY KEY,
  ulid VARCHAR(26) NOT NULL UNIQUE,
  tenant_id VARCHAR(26) NOT NULL,
  type ENUM('publishable', 'secret') NOT NULL,
  env ENUM('live', 'dev') NOT NULL DEFAULT 'live',
  scopes JSON NOT NULL DEFAULT '["read","write"]',
  ip_allowlist JSON NOT NULL DEFAULT '[]',
  rate_limit INT NOT NULL DEFAULT 1000,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP NULL,
  metadata JSON NOT NULL DEFAULT '{}',
  secret_hash VARCHAR(255) NULL,
  
  INDEX idx_tenant_id (tenant_id),
  INDEX idx_ulid (ulid),
  INDEX idx_expires (expires_at),
  INDEX idx_tenant_env (tenant_id, env)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

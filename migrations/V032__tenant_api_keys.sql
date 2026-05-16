-- V032: Tenant API Keys table
-- Provides per-tenant API key management similar to Clerk/Firebase

CREATE TABLE IF NOT EXISTS tenant_api_keys (
    id CHAR(32) PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    name VARCHAR(100) NOT NULL,
    prefix VARCHAR(20) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    secret_hash VARCHAR(64) NOT NULL,
    scope ENUM('read', 'write', 'admin', 'fullaccess') NOT NULL DEFAULT 'read',
    tier ENUM('free', 'standard', 'premium', 'enterprise') NOT NULL DEFAULT 'free',
    status ENUM('active', 'deprecated', 'revoked') NOT NULL DEFAULT 'active',
    ip_allowlist JSON DEFAULT ('[]'),
    rate_limit INT NOT NULL DEFAULT 60,
    allowed_origins JSON DEFAULT ('[]'),
    deprecated_at TIMESTAMP NULL,
    revoked_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_tenant_id (tenant_id),
    INDEX idx_key_hash (key_hash),
    INDEX idx_status (status),
    INDEX idx_tenant_status (tenant_id, status),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


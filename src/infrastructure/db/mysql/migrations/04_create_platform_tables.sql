-- Apps
CREATE TABLE IF NOT EXISTS apps (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(20) NOT NULL,
    redirect_uris JSON NOT NULL,
    allowed_origins JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_apps_client_id (client_id),
    INDEX idx_apps_tenant (tenant_id)
);

-- App Secrets
CREATE TABLE IF NOT EXISTS app_secrets (
    app_id VARCHAR(36) NOT NULL,
    tenant_id VARCHAR(36) NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    PRIMARY KEY (app_id, secret_hash),
    INDEX idx_app_secrets_tenant (tenant_id)
);

-- Domains
CREATE TABLE IF NOT EXISTS domains (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    domain_name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    dns_txt_record VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP NULL,
    UNIQUE KEY uk_domain_name (domain_name),
    INDEX idx_domains_tenant (tenant_id)
);

-- Webhooks
CREATE TABLE IF NOT EXISTS webhooks (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    app_id VARCHAR(36) NOT NULL,
    url TEXT NOT NULL,
    events JSON NOT NULL,
    secret_key VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    failure_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_webhooks_tenant (tenant_id),
    INDEX idx_webhooks_app (app_id)
);

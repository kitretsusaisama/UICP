-- Platform Identity Tables - Superadmin Governance Layer
-- V033

CREATE TABLE IF NOT EXISTS platform_identities (
    id VARCHAR(26) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    mfa_type VARCHAR(20) DEFAULT 'totp',
    mfa_secret VARCHAR(255),
    mfa_enabled BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'active',
    risk_score DECIMAL(5,4) DEFAULT 0.0,
    risk_level VARCHAR(20) DEFAULT 'low',
    last_login_at TIMESTAMP NULL,
    last_login_ip VARCHAR(45),
    last_login_device VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS platform_roles (
    id VARCHAR(50) PRIMARY KEY,
    type VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    assignment_type VARCHAR(20) DEFAULT 'permanent',
    is_system BOOLEAN DEFAULT TRUE,
    can_assign BOOLEAN DEFAULT FALSE,
    can_delegate BOOLEAN DEFAULT FALSE,
    inheritance_level INT DEFAULT 0,
    parent_role_id VARCHAR(50),
    permissions JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS platform_api_keys (
    id VARCHAR(26) PRIMARY KEY,
    ulid VARCHAR(26) NOT NULL UNIQUE,
    platform_identity_id VARCHAR(26) NOT NULL,
    type VARCHAR(20) NOT NULL,
    env VARCHAR(10) NOT NULL,
    scopes JSON NOT NULL,
    ip_allowlist JSON DEFAULT ('[]'),
    rate_limit INT DEFAULT 10000,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL,
    last_used_ip VARCHAR(45),
    metadata JSON DEFAULT ('{}'),
    secret_hash VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS platform_identity_role_assignments (
    id VARCHAR(36) PRIMARY KEY,
    platform_identity_id VARCHAR(26) NOT NULL,
    role_id VARCHAR(50) NOT NULL,
    role_type VARCHAR(50) NOT NULL,
    assignment_type VARCHAR(20) NOT NULL,
    assigned_by VARCHAR(26) NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activated_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    justification TEXT,
    deactivated_at TIMESTAMP NULL,
    deactivation_reason TEXT
);
-- Roles
CREATE TABLE IF NOT EXISTS roles (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    version INT NOT NULL DEFAULT 1,
    permissions JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_roles_tenant_name (tenant_id, name),
    INDEX idx_roles_tenant (tenant_id)
);

-- Role Assignments
CREATE TABLE IF NOT EXISTS role_assignments (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    assigned_by VARCHAR(36) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    UNIQUE KEY uk_role_assignment (tenant_id, user_id, role_id),
    INDEX idx_assignments_tenant_user (tenant_id, user_id)
);

-- ABAC Policies
CREATE TABLE IF NOT EXISTS abac_policies (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    effect VARCHAR(10) NOT NULL,
    conditions JSON NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_policies_tenant_name (tenant_id, name),
    INDEX idx_policies_tenant (tenant_id)
);

-- Policy Attachments (To link policies to roles/users/resources - for this implementation we assume they apply globally per tenant or are attached to roles)
CREATE TABLE IF NOT EXISTS policy_attachments (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    policy_id VARCHAR(36) NOT NULL,
    target_type VARCHAR(50) NOT NULL, -- e.g., 'role', 'user'
    target_id VARCHAR(36) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_policy_attachment (tenant_id, policy_id, target_type, target_id),
    INDEX idx_attachments_target (tenant_id, target_type, target_id)
);

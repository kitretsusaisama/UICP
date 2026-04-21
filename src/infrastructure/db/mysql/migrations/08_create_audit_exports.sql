CREATE TABLE IF NOT EXISTS audit_exports (
    id CHAR(26) PRIMARY KEY,
    tenant_id CHAR(26) NOT NULL,
    status ENUM('pending', 'processing', 'completed', 'failed') NOT NULL DEFAULT 'pending',
    file_path VARCHAR(255),
    created_by CHAR(26) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    error_message TEXT,
    INDEX idx_audit_exports_tenant (tenant_id)
);

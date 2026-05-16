-- -- V035: Seed Compatibility Fix
-- -- Add missing columns to existing tables for seed script compatibility

-- -- 1. Add missing columns to tenant_api_keys for seed script compatibility
ALTER TABLE tenant_api_keys ADD COLUMN ulid VARCHAR(26) AFTER id;
ALTER TABLE tenant_api_keys ADD COLUMN user_id BINARY(16) AFTER tenant_id;
ALTER TABLE tenant_api_keys ADD COLUMN type VARCHAR(20) AFTER user_id;
ALTER TABLE tenant_api_keys ADD COLUMN env VARCHAR(10) AFTER type;
ALTER TABLE tenant_api_keys ADD COLUMN scopes JSON AFTER env;
ALTER TABLE tenant_api_keys ADD COLUMN metadata JSON AFTER scopes;

-- -- 2. Add missing columns to abac_policies for seed script compatibility
ALTER TABLE abac_policies ADD COLUMN description TEXT AFTER name;
ALTER TABLE abac_policies ADD COLUMN conditions JSON AFTER effect;
ALTER TABLE abac_policies ADD COLUMN status VARCHAR(20) DEFAULT 'active' AFTER conditions;
ALTER TABLE user_roles DROP PRIMARY KEY, ADD PRIMARY KEY (user_id, role_id, tenant_id);
-- -- Migration completed
-- INSERT INTO schema_versions (version, description, applied_at)
-- VALUES (35, 'seed_compatibility', NOW())
-- ON DUPLICATE KEY UPDATE applied_at = NOW();
SELECT 1;

import { TenantApiKey } from '../entities/tenant-api-key.entity';

export interface ITenantApiKeyRepository {
  save(key: TenantApiKey): Promise<void>;
  findById(id: string, tenantId: string): Promise<TenantApiKey | null>;
  findByKeyHash(keyHash: string): Promise<TenantApiKey | null>;
  findByTenant(tenantId: string): Promise<TenantApiKey[]>;
  findActiveByTenant(tenantId: string): Promise<TenantApiKey[]>;
  delete(id: string, tenantId: string): Promise<void>;
  updateLastUsed(id: string, tenantId: string): Promise<void>;
}

export const TENANT_API_KEY_REPOSITORY = 'TENANT_API_KEY_REPOSITORY';
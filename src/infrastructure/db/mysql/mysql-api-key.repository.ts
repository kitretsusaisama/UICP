import { Injectable } from '@nestjs/common';
import { IApiKeyRepository } from '../../../domain/repositories/api-key.repository.interface';
import { ApiKeyEntity, ApiKeyType, ApiKeyEnv, ApiKeyScope } from '../../../domain/entities/api-key.entity';

interface ApiKeyRow {
  id: string;
  ulid: string;
  tenant_id: string;
  type: string;
  env: string;
  scopes: string;
  ip_allowlist: string;
  rate_limit: number;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  metadata: string;
  secret_hash: string | null;
}

@Injectable()
export class MySqlApiKeyRepository implements IApiKeyRepository {
  async findByUlid(ulid: string): Promise<ApiKeyEntity | null> {
    // TODO: Implement with actual MySQL query
    // Query: SELECT * FROM api_keys WHERE ulid = ? AND revoked_at IS NULL
    return null;
  }

  async findByTenantId(tenantId: string): Promise<ApiKeyEntity[]> {
    // TODO: Implement with actual MySQL query
    // Query: SELECT * FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC
    return [];
  }

  async findById(id: string): Promise<ApiKeyEntity | null> {
    // TODO: Implement with actual MySQL query
    return null;
  }

  async save(entity: ApiKeyEntity): Promise<ApiKeyEntity> {
    // TODO: Implement with actual MySQL upsert
    return entity;
  }

  async delete(id: string): Promise<void> {
    // TODO: Implement with actual MySQL delete
  }

  private rowToEntity(row: ApiKeyRow): ApiKeyEntity {
    return new ApiKeyEntity({
      id: row.id,
      ulid: row.ulid,
      tenantId: row.tenant_id,
      type: row.type as ApiKeyType,
      env: row.env as ApiKeyEnv,
      scopes: JSON.parse(row.scopes) as ApiKeyScope[],
      ipAllowlist: JSON.parse(row.ip_allowlist) as string[],
      rateLimit: row.rate_limit,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at ?? undefined,
      metadata: JSON.parse(row.metadata),
      secretHash: row.secret_hash ?? undefined,
    });
  }
}

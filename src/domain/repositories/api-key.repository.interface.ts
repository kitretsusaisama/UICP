import { ApiKeyEntity } from '../entities/api-key.entity';

export interface IApiKeyRepository {
  findByUlid(ulid: string): Promise<ApiKeyEntity | null>;
  findByTenantId(tenantId: string): Promise<ApiKeyEntity[]>;
  findById(id: string): Promise<ApiKeyEntity | null>;
  save(entity: ApiKeyEntity): Promise<ApiKeyEntity>;
  delete(id: string): Promise<void>;
}
import { PlatformApiKeyEntity } from '../../entities/platform/platform-api-key.entity';

export interface IPlatformApiKeyRepository {
  findByUlid(ulid: string): Promise<PlatformApiKeyEntity | null>;
  findById(id: string): Promise<PlatformApiKeyEntity | null>;
  findByPlatformIdentityId(platformIdentityId: string): Promise<PlatformApiKeyEntity[]>;
  findAll(): Promise<PlatformApiKeyEntity[]>;
  save(entity: PlatformApiKeyEntity): Promise<PlatformApiKeyEntity>;
  delete(id: string): Promise<void>;
}

export const PLATFORM_API_KEY_REPOSITORY = 'PLATFORM_API_KEY_REPOSITORY';
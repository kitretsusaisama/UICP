import { PlatformIdentity } from '../../entities/platform/platform-identity.entity';

export interface IPlatformIdentityRepository {
  findById(id: string): Promise<PlatformIdentity | null>;
  findByEmail(email: string): Promise<PlatformIdentity | null>;
  findAll(): Promise<PlatformIdentity[]>;
  findByStatus(status: string): Promise<PlatformIdentity[]>;
  findByRiskLevel(level: string): Promise<PlatformIdentity[]>;
  save(entity: PlatformIdentity): Promise<PlatformIdentity>;
  delete(id: string): Promise<void>;
}

export const PLATFORM_IDENTITY_REPOSITORY = 'PLATFORM_IDENTITY_REPOSITORY';
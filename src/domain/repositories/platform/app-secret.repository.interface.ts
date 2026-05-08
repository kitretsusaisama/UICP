import { AppSecret } from '../../entities/platform/app-secret.entity';

export const APP_SECRET_REPOSITORY = 'APP_SECRET_REPOSITORY';

export interface IAppSecretRepository {
  save(secret: AppSecret): Promise<void>;
  findByAppId(appId: string, tenantId: string): Promise<AppSecret[]>;
  findByHash(appId: string, tenantId: string, secretHash: string): Promise<AppSecret | null>;
}

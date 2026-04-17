import { App } from '../../entities/platform/app.entity';

export const APP_REPOSITORY = 'APP_REPOSITORY';

export interface IAppRepository {
  save(app: App): Promise<void>;
  findByIdAndTenant(id: string, tenantId: string): Promise<App | null>;
  findByTenant(tenantId: string): Promise<App[]>;
}

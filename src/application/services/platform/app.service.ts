import { Injectable, Inject, NotFoundException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { randomBytes } from 'crypto';
import { IAppRepository, APP_REPOSITORY } from '../../../domain/repositories/platform/app.repository.interface';
import { App, AppType } from '../../../domain/entities/platform/app.entity';

@Injectable()
export class AppService {
  constructor(
    @Inject(APP_REPOSITORY) private readonly appRepository: IAppRepository,
  ) {}

  async registerApp(
    tenantId: string,
    name: string,
    type: AppType,
    redirectUris: string[] = [],
    allowedOrigins: string[] = []
  ): Promise<App> {

    const clientId = `client_${randomBytes(16).toString('hex')}`;

    const app = new App({
      id: uuidv4(),
      tenantId,
      clientId,
      name,
      type,
      redirectUris,
      allowedOrigins,
    });

    await this.appRepository.save(app);
    return app;
  }

  async listApps(tenantId: string): Promise<App[]> {
    return this.appRepository.findByTenant(tenantId);
  }

  async getApp(id: string, tenantId: string): Promise<App> {
    const app = await this.appRepository.findByIdAndTenant(id, tenantId);
    if (!app) {
      throw new NotFoundException('App not found');
    }
    return app;
  }

  async updateAppMetadata(
    id: string,
    tenantId: string,
    redirectUris: string[],
    allowedOrigins: string[]
  ): Promise<App> {
    const app = await this.getApp(id, tenantId);

    app.updateMetadata(redirectUris, allowedOrigins);

    await this.appRepository.save(app);
    return app;
  }
}

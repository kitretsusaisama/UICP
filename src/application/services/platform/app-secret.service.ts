import { Injectable, Inject, NotFoundException, BadRequestException } from '@nestjs/common';
import { randomBytes, createHash } from 'crypto';
import { IAppSecretRepository, APP_SECRET_REPOSITORY } from '../../../domain/repositories/platform/app-secret.repository.interface';
import { AppSecret } from '../../../domain/entities/platform/app-secret.entity';
import { IAppRepository, APP_REPOSITORY } from '../../../domain/repositories/platform/app.repository.interface';

@Injectable()
export class AppSecretService {
  constructor(
    @Inject(APP_SECRET_REPOSITORY) private readonly secretRepository: IAppSecretRepository,
    @Inject(APP_REPOSITORY) private readonly appRepository: IAppRepository,
  ) {}

  async generateSecret(appId: string, tenantId: string): Promise<{ secretKey: string, secretHash: string }> {
    const app = await this.appRepository.findByIdAndTenant(appId, tenantId);
    if (!app) {
      throw new NotFoundException('App not found');
    }

    // Generate a strong random secret
    const rawSecret = `secret_${randomBytes(32).toString('hex')}`;

    // Hash it for storage
    const secretHash = createHash('sha256').update(rawSecret).digest('hex');

    const appSecret = new AppSecret({
      appId,
      tenantId,
      secretHash,
      status: 'active',
    });

    await this.secretRepository.save(appSecret);

    // Return the raw secret only once
    return { secretKey: rawSecret, secretHash };
  }

  async listSecrets(appId: string, tenantId: string): Promise<AppSecret[]> {
    return this.secretRepository.findByAppId(appId, tenantId);
  }

  async deprecateSecret(appId: string, tenantId: string, secretHash: string, gracePeriodSeconds = 3600): Promise<void> {
    const secret = await this.secretRepository.findByHash(appId, tenantId, secretHash);
    if (!secret) {
      throw new NotFoundException('Secret not found');
    }

    secret.deprecate(gracePeriodSeconds);
    await this.secretRepository.save(secret);
  }

  async revokeSecret(appId: string, tenantId: string, secretHash: string): Promise<void> {
    const secret = await this.secretRepository.findByHash(appId, tenantId, secretHash);
    if (!secret) {
      throw new NotFoundException('Secret not found');
    }

    secret.revoke();
    await this.secretRepository.save(secret);
  }

  async verifySecret(appId: string, tenantId: string, rawSecret: string): Promise<boolean> {
    const secretHash = createHash('sha256').update(rawSecret).digest('hex');
    const secret = await this.secretRepository.findByHash(appId, tenantId, secretHash);

    if (!secret) return false;

    return secret.isActive();
  }
}

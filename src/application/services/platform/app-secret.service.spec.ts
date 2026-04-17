import { AppSecretService } from './app-secret.service';
import { AppSecret } from '../../../domain/entities/platform/app-secret.entity';
import { App } from '../../../domain/entities/platform/app.entity';
import { NotFoundException } from '@nestjs/common';
import { createHash } from 'crypto';

describe('AppSecretService', () => {
  let appSecretService: AppSecretService;
  let appSecretRepositoryMock: any;
  let appRepositoryMock: any;

  beforeEach(() => {
    appSecretRepositoryMock = {
      save: jest.fn(),
      findByAppId: jest.fn(),
      findByHash: jest.fn(),
    };
    appRepositoryMock = {
      findByIdAndTenant: jest.fn(),
    };
    appSecretService = new AppSecretService(appSecretRepositoryMock, appRepositoryMock);
  });

  it('should generate a new secret for an existing app', async () => {
    appRepositoryMock.findByIdAndTenant.mockResolvedValue(new App({
      id: 'app-1',
      tenantId: 'tenant-1',
      clientId: 'client-1',
      name: 'Test App',
      type: 'public',
      redirectUris: [],
      allowedOrigins: []
    }));

    const result = await appSecretService.generateSecret('app-1', 'tenant-1');
    expect(result.secretKey).toMatch(/^secret_/);
    expect(result.secretHash).toBeDefined();
    expect(appSecretRepositoryMock.save).toHaveBeenCalled();
  });

  it('should throw NotFoundException when generating secret for non-existent app', async () => {
    appRepositoryMock.findByIdAndTenant.mockResolvedValue(null);
    await expect(appSecretService.generateSecret('app-1', 'tenant-1')).rejects.toThrow(NotFoundException);
  });

  it('should verify a valid secret', async () => {
    const rawSecret = 'secret_123';
    const secretHash = createHash('sha256').update(rawSecret).digest('hex');

    appSecretRepositoryMock.findByHash.mockResolvedValue(new AppSecret({
      appId: 'app-1',
      tenantId: 'tenant-1',
      secretHash,
      status: 'active'
    }));

    const isValid = await appSecretService.verifySecret('app-1', 'tenant-1', rawSecret);
    expect(isValid).toBe(true);
  });

  it('should reject an invalid secret', async () => {
    appSecretRepositoryMock.findByHash.mockResolvedValue(null);
    const isValid = await appSecretService.verifySecret('app-1', 'tenant-1', 'secret_invalid');
    expect(isValid).toBe(false);
  });

  it('should deprecate a secret', async () => {
    const secret = new AppSecret({
      appId: 'app-1',
      tenantId: 'tenant-1',
      secretHash: 'hash-123',
      status: 'active'
    });
    appSecretRepositoryMock.findByHash.mockResolvedValue(secret);

    await appSecretService.deprecateSecret('app-1', 'tenant-1', 'hash-123');
    expect(secret.status).toBe('deprecated');
    expect(secret.expiresAt).toBeDefined();
    expect(appSecretRepositoryMock.save).toHaveBeenCalledWith(secret);
  });

  it('should revoke a secret', async () => {
    const secret = new AppSecret({
      appId: 'app-1',
      tenantId: 'tenant-1',
      secretHash: 'hash-123',
      status: 'active'
    });
    appSecretRepositoryMock.findByHash.mockResolvedValue(secret);

    await appSecretService.revokeSecret('app-1', 'tenant-1', 'hash-123');
    expect(secret.status).toBe('revoked');
    expect(secret.isActive()).toBe(false);
    expect(appSecretRepositoryMock.save).toHaveBeenCalledWith(secret);
  });
});

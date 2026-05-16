import { Injectable, Inject, NotFoundException, BadRequestException, Logger } from '@nestjs/common';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { TenantApiKey, ApiKeyScope, ApiKeyTier, ApiKeyStatus } from '../../domain/entities/tenant-api-key.entity';
import { ITenantApiKeyRepository, TENANT_API_KEY_REPOSITORY } from '../../domain/repositories/tenant-api-key.repository.interface';
import { createHash, createHmac } from 'crypto';

export interface CreateApiKeyRequest {
  tenantId: string;
  name: string;
  scope?: ApiKeyScope;
  tier?: ApiKeyTier;
  ipAllowlist?: string[];
  rateLimit?: number;
  allowedOrigins?: string[];
  expiresInDays?: number;
}

export interface ApiKeyResponse {
  id: string;
  name: string;
  publicKey: string;
  secretKey: string;
  scope: ApiKeyScope;
  tier: ApiKeyTier;
  status: ApiKeyStatus;
  rateLimit: number;
  ipAllowlist: string[];
  allowedOrigins: string[];
  expiresAt?: string;
  createdAt: string;
}

@Injectable()
export class TenantApiKeyService {
  private readonly logger = new Logger(TenantApiKeyService.name);

  constructor(
    @Inject(TENANT_API_KEY_REPOSITORY)
    private readonly repository: ITenantApiKeyRepository,
  ) {}

  async createApiKey(request: CreateApiKeyRequest): Promise<ApiKeyResponse> {
    const tenantId = TenantId.from(request.tenantId);

    const expiresAt = request.expiresInDays
      ? new Date(Date.now() + request.expiresInDays * 24 * 60 * 60 * 1000)
      : undefined;

    const { key, publicKey, secretKey } = TenantApiKey.create({
      tenantId,
      name: request.name,
      scope: request.scope,
      tier: request.tier,
      ipAllowlist: request.ipAllowlist,
      rateLimit: request.rateLimit,
      allowedOrigins: request.allowedOrigins,
      expiresAt,
    });

    await this.repository.save(key);

    this.logger.log({ tenantId: request.tenantId, keyId: key.id, name: request.name }, 'API key created');

    return {
      id: key.id,
      name: key.name,
      publicKey,
      secretKey,
      scope: key.scope,
      tier: key.tier,
      status: key.status,
      rateLimit: key.rateLimit,
      ipAllowlist: key.ipAllowlist,
      allowedOrigins: key.allowedOrigins,
      expiresAt: key.expiresAt?.toISOString(),
      createdAt: key.createdAt.toISOString(),
    };
  }

  async listApiKeys(tenantId: string): Promise<TenantApiKey[]> {
    return this.repository.findByTenant(tenantId);
  }

  async getApiKey(id: string, tenantId: string): Promise<TenantApiKey> {
    const key = await this.repository.findById(id, tenantId);
    if (!key) {
      throw new NotFoundException('API key not found');
    }
    return key;
  }

  async rotateApiKey(id: string, tenantId: string): Promise<ApiKeyResponse> {
    const oldKey = await this.getApiKey(id, tenantId);

    if (oldKey.status === 'revoked') {
      throw new BadRequestException('Cannot rotate a revoked key');
    }

    oldKey.deprecate(3600);
    await this.repository.save(oldKey);

    const { key, publicKey, secretKey } = TenantApiKey.create({
      tenantId: oldKey.tenantId,
      name: `${oldKey.name} (rotated)`,
      scope: oldKey.scope,
      tier: oldKey.tier,
      ipAllowlist: oldKey.ipAllowlist,
      rateLimit: oldKey.rateLimit,
      allowedOrigins: oldKey.allowedOrigins,
    });

    await this.repository.save(key);

    this.logger.log({ tenantId, keyId: id, newKeyId: key.id }, 'API key rotated');

    return {
      id: key.id,
      name: key.name,
      publicKey,
      secretKey,
      scope: key.scope,
      tier: key.tier,
      status: key.status,
      rateLimit: key.rateLimit,
      ipAllowlist: key.ipAllowlist,
      allowedOrigins: key.allowedOrigins,
      createdAt: key.createdAt.toISOString(),
    };
  }

  async deprecateApiKey(id: string, tenantId: string, gracePeriodSeconds = 3600): Promise<void> {
    const key = await this.getApiKey(id, tenantId);
    key.deprecate(gracePeriodSeconds);
    await this.repository.save(key);
    this.logger.log({ tenantId, keyId: id }, 'API key deprecated');
  }

  async revokeApiKey(id: string, tenantId: string): Promise<void> {
    const key = await this.getApiKey(id, tenantId);
    key.revoke();
    await this.repository.save(key);
    this.logger.log({ tenantId, keyId: id }, 'API key revoked');
  }

  async updateApiKey(
    id: string,
    tenantId: string,
    updates: Partial<{
      name: string;
      scope: ApiKeyScope;
      tier: ApiKeyTier;
      ipAllowlist: string[];
      rateLimit: number;
      allowedOrigins: string[];
    }>,
  ): Promise<TenantApiKey> {
    const key = await this.getApiKey(id, tenantId);
    key.update(updates);
    await this.repository.save(key);
    return key;
  }

  async deleteApiKey(id: string, tenantId: string): Promise<void> {
    const key = await this.getApiKey(id, tenantId);
    if (key.status === 'active') {
      throw new BadRequestException('Cannot delete an active key. Revoke it first.');
    }
    await this.repository.delete(id, tenantId);
    this.logger.log({ tenantId, keyId: id }, 'API key deleted');
  }

  async verifyAndAuthenticate(
    publicKey: string,
    secretKey: string,
    clientIp?: string,
  ): Promise<{ tenantId: string; key: TenantApiKey } | null> {
    const keyHash = createHash('sha256').update(publicKey).digest('hex');
    const key = await this.repository.findByKeyHash(keyHash);

    if (!key) {
      return null;
    }

    if (!key.verifySecret(secretKey)) {
      return null;
    }

    if (!key.isActive()) {
      return null;
    }

    if (clientIp && !key.isIpAllowed(clientIp)) {
      return null;
    }

    await this.repository.updateLastUsed(key.id, key.tenantId.toString());
    key.updateLastUsed();

    return { tenantId: key.tenantId.toString(), key };
  }

  static signRequest(secretKey: string, body: string, timestamp: number): string {
    const payload = `${timestamp}.${body}`;
    return createHmac('sha256', secretKey).update(payload).digest('hex');
  }

  static verifySignature(secretKey: string, body: string, timestamp: number, signature: string): boolean {
    const expected = this.signRequest(secretKey, body, timestamp);
    return createHash('sha256').update(expected).digest('hex') === createHash('sha256').update(signature).digest('hex');
  }
}
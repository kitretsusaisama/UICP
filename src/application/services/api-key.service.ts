import { Injectable } from '@nestjs/common';
import { ulid } from 'ulid';
import { IApiKeyRepository } from '../../domain/repositories/api-key.repository.interface';
import { ApiKeyEntity, ApiKeyType, ApiKeyEnv, ApiKeyScope, ApiKeyProps } from '../../domain/entities/api-key.entity';
import { generateApiKey } from '../../shared/utils/api-key-parser';

export interface CreateApiKeyInput {
  tenantId: string;
  name?: string;
  scopes?: ApiKeyScope[];
  ipAllowlist?: string[];
  rateLimit?: number;
  expiresInDays?: number;
  env?: ApiKeyEnv;
  metadata?: Record<string, unknown>;
}

export interface CreateApiKeyOutput {
  publishableKey: string;
  secretKey: string;
  apiKey: ApiKeyEntity;
}

@Injectable()
export class ApiKeyService {
  private readonly hmacSecret: string;
  private readonly defaultExpiryDays = 90;

  constructor(private readonly apiKeyRepository: IApiKeyRepository) {
    this.hmacSecret = process.env.API_KEY_HMAC_SECRET || 'default-secret-change-in-prod';
  }

  async create(input: CreateApiKeyInput): Promise<CreateApiKeyOutput> {
    const keyUlid = ulid();
    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + (input.expiresInDays || this.defaultExpiryDays) * 24 * 60 * 60 * 1000
    );

    const props: ApiKeyProps = {
      id: ulid(),
      ulid: keyUlid,
      tenantId: input.tenantId,
      type: ApiKeyType.PUBLISHABLE,
      env: input.env || ApiKeyEnv.LIVE,
      scopes: input.scopes || [ApiKeyScope.READ, ApiKeyScope.WRITE],
      ipAllowlist: input.ipAllowlist || [],
      rateLimit: input.rateLimit || 1000,
      createdAt: now,
      expiresAt,
      metadata: { name: input.name || 'Default API Key' },
    };

    const publishableKey = generateApiKey(
      ApiKeyType.PUBLISHABLE,
      props.env,
      keyUlid,
      this.hmacSecret,
      input.tenantId
    );

    const secretUlid = ulid();
    const secretKey = generateApiKey(
      ApiKeyType.SECRET,
      props.env,
      secretUlid,
      this.hmacSecret,
      input.tenantId
    );

    const secretProps: ApiKeyProps = {
      ...props,
      id: ulid(),
      ulid: secretUlid,
      type: ApiKeyType.SECRET,
      secretHash: secretKey,
    };

    const secretEntity = new ApiKeyEntity(secretProps);
    await this.apiKeyRepository.save(secretEntity);

    const publishableEntity = new ApiKeyEntity(props);
    await this.apiKeyRepository.save(publishableEntity);

    return {
      publishableKey,
      secretKey,
      apiKey: publishableEntity,
    };
  }

  async listByTenant(tenantId: string): Promise<ApiKeyEntity[]> {
    return this.apiKeyRepository.findByTenantId(tenantId);
  }

  async getByUlid(ulid: string): Promise<ApiKeyEntity | null> {
    return this.apiKeyRepository.findByUlid(ulid);
  }

  async rotate(id: string, tenantId: string): Promise<CreateApiKeyOutput> {
    const existing = await this.apiKeyRepository.findById(id);
    if (!existing || existing.tenantId !== tenantId) {
      throw new Error('API key not found');
    }

    existing.revoke();
    await this.apiKeyRepository.save(existing);

    return this.create({
      tenantId,
      scopes: existing.scopes,
      ipAllowlist: existing.ipAllowlist,
      rateLimit: existing.rateLimit,
      env: existing.env,
      metadata: { ...existing.metadata, rotatedFrom: existing.ulid },
    });
  }

  async revoke(id: string, tenantId: string): Promise<void> {
    const key = await this.apiKeyRepository.findById(id);
    if (!key || key.tenantId !== tenantId) {
      throw new Error('API key not found');
    }
    key.revoke();
    await this.apiKeyRepository.save(key);
  }
}

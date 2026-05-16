import { Injectable, NotFoundException } from '@nestjs/common';
import { ulid } from 'ulid';
import { IPlatformApiKeyRepository } from '../../../domain/repositories/platform/platform-api-key.repository.interface';
import { PlatformApiKeyEntity } from '../../../domain/entities/platform/platform-api-key.entity';
import { ApiKeyType, ApiKeyEnv } from '../../../domain/entities/api-key.entity';
import { generateApiKey } from '../../../shared/utils/api-key-parser';

export interface CreatePlatformApiKeyInput {
  platformIdentityId: string;
  name?: string;
  scopes?: string[];
  ipAllowlist?: string[];
  rateLimit?: number;
  expiresInDays?: number;
  env?: ApiKeyEnv;
  metadata?: Record<string, unknown>;
}

export interface CreatePlatformApiKeyOutput {
  publishableKey: string;
  secretKey: string;
  apiKey: PlatformApiKeyEntity;
}

@Injectable()
export class PlatformApiKeyService {
  private readonly hmacSecret: string;
  private readonly defaultExpiryDays = 90;

  constructor(private readonly platformApiKeyRepository: IPlatformApiKeyRepository) {
    const secret = process.env.PLATFORM_API_KEY_HMAC_SECRET || process.env.API_KEY_HMAC_SECRET;
    if (!secret) {
      throw new Error('CRITICAL: PLATFORM_API_KEY_HMAC_SECRET or API_KEY_HMAC_SECRET environment variable is not set');
    }
    if (secret.length < 32) {
      throw new Error('CRITICAL: Platform HMAC secret must be at least 32 characters');
    }
    this.hmacSecret = secret;
  }

  async create(input: CreatePlatformApiKeyInput): Promise<CreatePlatformApiKeyOutput> {
    const keyUlid = ulid();
    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + (input.expiresInDays || this.defaultExpiryDays) * 24 * 60 * 60 * 1000
    );

    const scopes = input.scopes ?? ['read', 'write', 'admin'];

    const publishableEntity = PlatformApiKeyEntity.create({
      platformIdentityId: input.platformIdentityId,
      type: ApiKeyType.PUBLISHABLE,
      env: input.env ?? ApiKeyEnv.LIVE,
      scopes,
      ipAllowlist: input.ipAllowlist ?? [],
      rateLimit: input.rateLimit ?? 10000,
      createdAt: now,
      expiresAt,
      metadata: { name: input.name ?? 'Platform API Key' },
    });

    const secretUlid = ulid();
    const secretEntity = PlatformApiKeyEntity.create({
      id: ulid(),
      ulid: secretUlid,
      platformIdentityId: input.platformIdentityId,
      type: ApiKeyType.SECRET,
      env: input.env ?? ApiKeyEnv.LIVE,
      scopes,
      ipAllowlist: input.ipAllowlist ?? [],
      rateLimit: input.rateLimit ?? 10000,
      createdAt: now,
      expiresAt,
      metadata: { name: input.name ?? 'Platform API Key', isSecret: true },
    });

    const publishableKey = generateApiKey(
      ApiKeyType.PUBLISHABLE,
      publishableEntity.env,
      publishableEntity.ulid,
      this.hmacSecret,
      input.platformIdentityId
    );

    const secretKey = generateApiKey(
      ApiKeyType.SECRET,
      secretEntity.env,
      secretEntity.ulid,
      this.hmacSecret,
      input.platformIdentityId
    );

    await this.platformApiKeyRepository.save(secretEntity);
    await this.platformApiKeyRepository.save(publishableEntity);

    return {
      publishableKey,
      secretKey,
      apiKey: publishableEntity,
    };
  }

  async getByUlid(ulid: string): Promise<PlatformApiKeyEntity | null> {
    return this.platformApiKeyRepository.findByUlid(ulid);
  }

  async getById(id: string): Promise<PlatformApiKeyEntity> {
    const key = await this.platformApiKeyRepository.findById(id);
    if (!key) {
      throw new NotFoundException('Platform API key not found');
    }
    return key;
  }

  async listByIdentity(platformIdentityId: string): Promise<PlatformApiKeyEntity[]> {
    return this.platformApiKeyRepository.findByPlatformIdentityId(platformIdentityId);
  }

  async listAll(): Promise<PlatformApiKeyEntity[]> {
    return this.platformApiKeyRepository.findAll();
  }

  async recordUsage(id: string, ip: string): Promise<void> {
    const key = await this.getById(id);
    key.recordUsage(ip);
    await this.platformApiKeyRepository.save(key);
  }

  async rotate(id: string, platformIdentityId: string): Promise<CreatePlatformApiKeyOutput> {
    const existing = await this.platformApiKeyRepository.findById(id);
    if (!existing || existing.platformIdentityId !== platformIdentityId) {
      throw new NotFoundException('Platform API key not found');
    }

    existing.revoke();
    await this.platformApiKeyRepository.save(existing);

    return this.create({
      platformIdentityId,
      scopes: existing.scopes,
      ipAllowlist: existing.ipAllowlist,
      rateLimit: existing.rateLimit,
      env: existing.env,
      metadata: { ...existing.metadata, rotatedFrom: existing.ulid },
    });
  }

  async revoke(id: string, platformIdentityId: string): Promise<void> {
    const key = await this.platformApiKeyRepository.findById(id);
    if (!key || key.platformIdentityId !== platformIdentityId) {
      throw new NotFoundException('Platform API key not found');
    }
    key.revoke();
    await this.platformApiKeyRepository.save(key);
  }
}
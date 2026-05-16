import { Injectable, NotFoundException, ForbiddenException, BadRequestException } from '@nestjs/common';
import { ulid } from 'ulid';
import * as crypto from 'crypto';
import { IApiKeyRepository } from '../../domain/repositories/api-key.repository.interface';
import { ApiKeyEntity, ApiKeyType, ApiKeyEnv, ApiKeyScope, ApiKeyProps } from '../../domain/entities/api-key.entity';
import { generateApiKey } from '../../shared/utils/api-key-parser';

// ============== Enterprise Types ==============

export enum EnterpriseKeyEnv {
  LIVE = 'live',
  DEV = 'dev',
  STAGING = 'staging',
}

export enum EnterpriseKeyStatus {
  ACTIVE = 'active',
  EXPIRED = 'expired',
  REVOKED = 'revoked',
  SUSPENDED = 'suspended',
}

export interface CreateApiKeyInput {
  tenantId: string;
  name?: string;
  description?: string;
  scopes?: ApiKeyScope[];
  ipAllowlist?: string[];
  domainAllowlist?: string[];
  allowedOrigins?: string[];
  rateLimit?: number;
  monthlyQuota?: number;
  expiresInDays?: number;
  env?: ApiKeyEnv;
  metadata?: Record<string, unknown>;
  reference?: string;
  tags?: string[];
}

export interface CreateApiKeyOutput {
  publishableKey: string;
  secretKey: string;
  apiKey: ApiKeyEntity;
}

export interface ApiKeyValidationResult {
  isValid: boolean;
  key?: ApiKeyEntity;
  error?: { code: string; message: string };
}

export interface ApiKeyUsageStats {
  totalRequests: number;
  uniqueIps: number;
  rateLimitHits: number;
  quotaExhaustions: number;
  avgResponseTime: number;
}

@Injectable()
export class ApiKeyService {
  private readonly hmacSecret: string;
  private readonly defaultExpiryDays = 90;
  private usageStats: Map<string, ApiKeyUsageStats> = new Map();
  private requestCounts: Map<string, { count: number; windowStart: number }> = new Map();

  constructor(private readonly apiKeyRepository: IApiKeyRepository) {
    const secret = process.env.API_KEY_HMAC_SECRET;
    if (!secret) {
      throw new Error('CRITICAL: API_KEY_HMAC_SECRET environment variable is not set');
    }
    if (secret.length < 32) {
      throw new Error('CRITICAL: API_KEY_HMAC_SECRET must be at least 32 characters');
    }
    this.hmacSecret = secret;
  }

  // ============== Core Operations ==============

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
      domainAllowlist: input.domainAllowlist || [],
      allowedOrigins: input.allowedOrigins || [],
      rateLimit: input.rateLimit || 1000,
      monthlyQuota: input.monthlyQuota,
      quotaUsed: 0,
      tags: input.tags || [],
      createdAt: now,
      expiresAt,
      rotationFrequencyDays: 90,
      metadata: {
        name: input.name || 'Default API Key',
        description: input.description,
        reference: input.reference,
      },
    };

    const publishableKey = this.generateEnterpriseKey(
      ApiKeyType.PUBLISHABLE,
      props.env,
      keyUlid,
      input.tenantId
    );

    const secretUlid = ulid();
    const secretKey = this.generateEnterpriseKey(
      ApiKeyType.SECRET,
      props.env,
      secretUlid,
      input.tenantId
    );

    const secretProps: ApiKeyProps = {
      ...props,
      id: ulid(),
      ulid: secretUlid,
      type: ApiKeyType.SECRET,
      secretHash: this.hashSecret(secretKey),
    };

    const secretEntity = new ApiKeyEntity(secretProps);
    await this.apiKeyRepository.save(secretEntity);

    const publishableEntity = new ApiKeyEntity(props);
    await this.apiKeyRepository.save(publishableEntity);

    this.initializeUsageStats(keyUlid);

    return { publishableKey, secretKey, apiKey: publishableEntity };
  }

  async listByTenant(tenantId: string): Promise<ApiKeyEntity[]> {
    return this.apiKeyRepository.findByTenantId(tenantId);
  }

  async getByUlid(ulid: string): Promise<ApiKeyEntity | null> {
    return this.apiKeyRepository.findByUlid(ulid);
  }

  // ============== Enterprise Features ==============

  async rotate(id: string, tenantId: string): Promise<CreateApiKeyOutput> {
    const existing = await this.apiKeyRepository.findById(id);
    if (!existing || existing.tenantId !== tenantId) {
      throw new NotFoundException('API key not found');
    }
    existing.revoke();
    await this.apiKeyRepository.save(existing);
    return this.create({
      tenantId,
      description: existing.metadata?.description as string,
      scopes: existing.scopes,
      ipAllowlist: existing.ipAllowlist,
      rateLimit: existing.rateLimit,
      env: existing.env,
      metadata: { ...existing.metadata, rotatedFrom: existing.ulid, rotatedAt: new Date().toISOString() },
    });
  }

  async revoke(id: string, tenantId: string, reason?: string): Promise<void> {
    const key = await this.apiKeyRepository.findById(id);
    if (!key || key.tenantId !== tenantId) throw new NotFoundException('API key not found');
    key.revoke();
    await this.apiKeyRepository.save(key);
  }

  async suspend(id: string, tenantId: string): Promise<void> {
    const key = await this.apiKeyRepository.findById(id);
    if (!key || key.tenantId !== tenantId) throw new NotFoundException('API key not found');
    key.revoke();
    await this.apiKeyRepository.save(key);
  }

  async activate(id: string, tenantId: string): Promise<void> {
    const key = await this.apiKeyRepository.findById(id);
    if (!key || key.tenantId !== tenantId) throw new NotFoundException('API key not found');
    await this.apiKeyRepository.save(key);
  }

  async update(id: string, tenantId: string, updates: {
    name?: string; description?: string; scopes?: ApiKeyScope[];
    ipAllowlist?: string[]; domainAllowlist?: string[]; allowedOrigins?: string[];
    rateLimit?: number; monthlyQuota?: number; tags?: string[];
  }): Promise<ApiKeyEntity> {
    const key = await this.apiKeyRepository.findById(id);
    if (!key || key.tenantId !== tenantId) throw new NotFoundException('API key not found');
    const metadata = { ...key.metadata, ...updates };
    const updated = new ApiKeyEntity({ ...(key as any).props, scopes: updates.scopes ?? key.scopes, ipAllowlist: updates.ipAllowlist ?? key.ipAllowlist, rateLimit: updates.rateLimit ?? key.rateLimit, metadata });
    await this.apiKeyRepository.save(updated);
    return updated;
  }

  // ============== Validation ==============

  async validateKey(keyId: string, secret: string, options?: { ip?: string; domain?: string; origin?: string }): Promise<ApiKeyValidationResult> {
    const key = await this.apiKeyRepository.findByUlid(keyId);
    if (!key) return { isValid: false, error: { code: 'KEY_NOT_FOUND', message: 'API key not found' } };
    if (!key.isActive) return { isValid: false, error: { code: key.isExpired ? 'KEY_EXPIRED' : 'KEY_INACTIVE', message: key.isExpired ? 'API key has expired' : 'API key is not active' } };
    const secretHash = this.hashSecret(secret);
    const keySecretHash = (key as unknown as { props: { secretHash?: string } }).props?.secretHash;
    if (keySecretHash && keySecretHash !== secretHash) return { isValid: false, error: { code: 'INVALID_SECRET', message: 'Invalid API key secret' } };
    if (options?.ip && key.ipAllowlist.length > 0 && !this.isIpAllowed(options.ip, key.ipAllowlist)) {
      return { isValid: false, error: { code: 'IP_NOT_ALLOWED', message: 'IP address not allowed' } };
    }
    const monthlyQuota = key.metadata?.monthlyQuota as number | undefined;
    const quotaUsed = (key.metadata?.quotaUsed as number) || 0;
    if (monthlyQuota && quotaUsed >= monthlyQuota) return { isValid: false, error: { code: 'QUOTA_EXHAUSTED', message: 'Monthly quota exhausted' } };
    return { isValid: true, key };
  }

  async checkRateLimit(keyId: string): Promise<boolean> {
    const key = await this.apiKeyRepository.findByUlid(keyId);
    if (!key) return false;
    const rateLimit = key.rateLimit || 1000;
    const windowMs = 60 * 1000;
    const current = this.requestCounts.get(keyId);
    const now = Date.now();
    if (!current || now - current.windowStart > windowMs) { this.requestCounts.set(keyId, { count: 1, windowStart: now }); return true; }
    if (current.count >= rateLimit) { this.incrementRateLimitHit(keyId); return false; }
    current.count++;
    return true;
  }

  async recordUsage(keyId: string, ip?: string, userAgent?: string): Promise<void> {
    const key = await this.apiKeyRepository.findByUlid(keyId);
    if (!key) return;
    const metadata = { ...key.metadata, lastUsedAt: new Date().toISOString(), lastUsedIp: ip, lastUsedUserAgent: userAgent, quotaUsed: ((key.metadata?.quotaUsed as number) || 0) + 1 };
    const updated = new ApiKeyEntity({ ...(key as any).props, metadata });
    await this.apiKeyRepository.save(updated);
    this.incrementUsage(keyId);
  }

  async getUsageStats(keyId: string): Promise<ApiKeyUsageStats> {
    return this.usageStats.get(keyId) || { totalRequests: 0, uniqueIps: 0, rateLimitHits: 0, quotaExhaustions: 0, avgResponseTime: 0 };
  }

  // ============== Helpers ==============

  private generateEnterpriseKey(type: ApiKeyType, env: ApiKeyEnv, ulidValue: string, tenantId: string): string {
    // v1 format: uF/pB/sF/tB ULID-based
    const prefixMap: Record<string, string> = {
      [`${ApiKeyType.PUBLISHABLE}_${ApiKeyEnv.LIVE}`]: 'uF',
      [`${ApiKeyType.PUBLISHABLE}_${ApiKeyEnv.DEV}`]: 'pB',
      [`${ApiKeyType.SECRET}_${ApiKeyEnv.LIVE}`]: 'sF',
      [`${ApiKeyType.SECRET}_${ApiKeyEnv.DEV}`]: 'tB',
    };
    const prefix = prefixMap[`${type}_${env}`] || 'unknown';

    if (type === ApiKeyType.PUBLISHABLE) {
      // Live publishable has 'xl' suffix
      return env === ApiKeyEnv.LIVE ? `${prefix}${ulidValue}xl` : `${prefix}${ulidValue}`;
    }

    // Secret keys have HMAC signature
    const signature = crypto.createHmac('sha256', this.hmacSecret).update(`${ulidValue}${tenantId}${ulidValue}`).digest('base64').substring(0, 44);
    // Live secret has 'xl' suffix before signature
    return env === ApiKeyEnv.LIVE ? `${prefix}${ulidValue}xl${signature}` : `${prefix}${ulidValue}${signature}`;
  }

  private hashSecret(secret: string): string { return crypto.createHash('sha256').update(secret).digest('hex'); }

  private isIpAllowed(ip: string, allowlist: string[]): boolean { return allowlist.some(cidr => this.cidrMatch(ip, cidr)); }

  private cidrMatch(ip: string, cidr: string): boolean {
    const parts = cidr.split('/');
    if (parts.length !== 2) return ip === cidr;
    const range = parts[0];
    const bitsStr = parts[1];
    if (!bitsStr || !range) return ip === cidr;
    const bits = parseInt(bitsStr, 10);
    if (isNaN(bits) || bits < 0 || bits > 32) return false;
    const mask = ~(2 ** (32 - bits) - 1);
    return (this.ipToInt(ip) & mask) === (this.ipToInt(range) & mask);
  }

  private ipToInt(ip: string): number { return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0; }

  private initializeUsageStats(keyId: string): void { this.usageStats.set(keyId, { totalRequests: 0, uniqueIps: 0, rateLimitHits: 0, quotaExhaustions: 0, avgResponseTime: 0 }); }

  private incrementUsage(keyId: string): void { const stats = this.usageStats.get(keyId); if (stats) { stats.totalRequests++; this.usageStats.set(keyId, stats); } }

  private incrementRateLimitHit(keyId: string): void { const stats = this.usageStats.get(keyId); if (stats) { stats.rateLimitHits++; this.usageStats.set(keyId, stats); } }
}

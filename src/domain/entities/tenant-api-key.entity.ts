import { randomBytes, createHash, timingSafeEqual } from 'crypto';
import { TenantId } from '../value-objects/tenant-id.vo';

export type ApiKeyScope = 'read' | 'write' | 'admin' | 'fullaccess';
export type ApiKeyTier = 'free' | 'standard' | 'premium' | 'enterprise';
export type ApiKeyStatus = 'active' | 'deprecated' | 'revoked';

export interface TenantApiKeyProps {
  id: string;
  tenantId: TenantId;
  name: string;
  prefix: string;
  keyHash: string;
  secretHash: string;
  scope: ApiKeyScope;
  tier: ApiKeyTier;
  status: ApiKeyStatus;
  ipAllowlist: string[];
  rateLimit: number;
  allowedOrigins: string[];
  deprecatedAt?: Date;
  revokedAt?: Date;
  expiresAt?: Date;
  lastUsedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export class TenantApiKey {
  private readonly props: TenantApiKeyProps;

  private constructor(props: TenantApiKeyProps) {
    this.props = props;
  }

  static create(params: {
    tenantId: TenantId;
    name: string;
    scope?: ApiKeyScope;
    tier?: ApiKeyTier;
    ipAllowlist?: string[];
    rateLimit?: number;
    allowedOrigins?: string[];
    expiresAt?: Date;
  }): { key: TenantApiKey; publicKey: string; secretKey: string } {
    const id = randomBytes(16).toString('hex');
    const environment = process.env.NODE_ENV === 'production' ? 'live' : 'test';
    const randomPart = randomBytes(12).toString('hex');

    const publicKey = `uicp_pk_${environment}_${randomPart}`;
    const secretKey = `uicp_sk_${environment}_${randomPart}`;

    const keyHash = createHash('sha256').update(publicKey).digest('hex');
    const secretHash = createHash('sha256').update(secretKey).digest('hex');

    const now = new Date();

    const key = new TenantApiKey({
      id,
      tenantId: params.tenantId,
      name: params.name,
      prefix: publicKey.slice(0, 20),
      keyHash,
      secretHash,
      scope: params.scope ?? 'read',
      tier: params.tier ?? 'free',
      status: 'active',
      ipAllowlist: params.ipAllowlist ?? [],
      rateLimit: params.rateLimit ?? 60,
      allowedOrigins: params.allowedOrigins ?? [],
      expiresAt: params.expiresAt,
      createdAt: now,
      updatedAt: now,
    });

    return { key, publicKey, secretKey };
  }

  static fromProps(props: TenantApiKeyProps): TenantApiKey {
    return new TenantApiKey(props);
  }

  static fromStorage(row: Record<string, unknown>): TenantApiKey {
    return new TenantApiKey({
      id: row.id as string,
      tenantId: TenantId.from(row.tenant_id as string),
      name: row.name as string,
      prefix: row.prefix as string,
      keyHash: row.key_hash as string,
      secretHash: row.secret_hash as string,
      scope: row.scope as ApiKeyScope,
      tier: row.tier as ApiKeyTier,
      status: row.status as ApiKeyStatus,
      ipAllowlist: JSON.parse((row.ip_allowlist as string) || '[]'),
      rateLimit: row.rate_limit as number,
      allowedOrigins: JSON.parse((row.allowed_origins as string) || '[]'),
      deprecatedAt: row.deprecated_at ? new Date(row.deprecated_at as string) : undefined,
      revokedAt: row.revoked_at ? new Date(row.revoked_at as string) : undefined,
      expiresAt: row.expires_at ? new Date(row.expires_at as string) : undefined,
      lastUsedAt: row.last_used_at ? new Date(row.last_used_at as string) : undefined,
      createdAt: new Date(row.created_at as string),
      updatedAt: new Date(row.updated_at as string),
    });
  }

  get id(): string { return this.props.id; }
  get tenantId(): TenantId { return this.props.tenantId; }
  get name(): string { return this.props.name; }
  get prefix(): string { return this.props.prefix; }
  get keyHash(): string { return this.props.keyHash; }
  get scope(): ApiKeyScope { return this.props.scope; }
  get tier(): ApiKeyTier { return this.props.tier; }
  get status(): ApiKeyStatus { return this.props.status; }
  get ipAllowlist(): string[] { return this.props.ipAllowlist; }
  get rateLimit(): number { return this.props.rateLimit; }
  get allowedOrigins(): string[] { return this.props.allowedOrigins; }
  get deprecatedAt(): Date | undefined { return this.props.deprecatedAt; }
  get revokedAt(): Date | undefined { return this.props.revokedAt; }
  get expiresAt(): Date | undefined { return this.props.expiresAt; }
  get lastUsedAt(): Date | undefined { return this.props.lastUsedAt; }
  get createdAt(): Date { return this.props.createdAt; }

  isActive(): boolean {
    if (this.props.status !== 'active') return false;
    if (this.props.expiresAt && this.props.expiresAt < new Date()) return false;
    return true;
  }

  isScopeAllowed(action: string): boolean {
    const scopeHierarchy: Record<ApiKeyScope, string[]> = {
      read: ['read'],
      write: ['read', 'write'],
      admin: ['read', 'write', 'admin'],
      fullaccess: ['read', 'write', 'admin', 'fullaccess'],
    };
    return scopeHierarchy[this.props.scope].includes(action);
  }

  isIpAllowed(ip: string): boolean {
    if (this.props.ipAllowlist.length === 0) return true;
    return this.props.ipAllowlist.some(allowed => {
      if (allowed.includes('/')) {
        return this.cidrMatch(ip, allowed);
      }
      return ip === allowed;
    });
  }

  private cidrMatch(ip: string, cidr: string): boolean {
    const parts = cidr.split('/');
    if (parts.length !== 2) return false;
    const range = parts[0]!;
    const bitsStr = parts[1]!;
    const bits = parseInt(bitsStr, 10);
    if (isNaN(bits) || bits < 0 || bits > 32) return false;
    const mask = ~(2 ** (32 - bits) - 1);
    const ipInt = this.ipToInt(ip);
    const rangeInt = this.ipToInt(range);
    return (ipInt & mask) === (rangeInt & mask);
  }

  private ipToInt(ip: string): number {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
  }

  verifySecret(rawSecret: string): boolean {
    const secretHash = createHash('sha256').update(rawSecret).digest('hex');
    return timingSafeEqual(Buffer.from(secretHash), Buffer.from(this.props.secretHash));
  }

  deprecate(gracePeriodSeconds = 3600): void {
    if (this.props.status !== 'active') return;
    this.props.status = 'deprecated';
    this.props.deprecatedAt = new Date(Date.now() + gracePeriodSeconds * 1000);
    this.props.updatedAt = new Date();
  }

  revoke(): void {
    this.props.status = 'revoked';
    this.props.revokedAt = new Date();
    this.props.updatedAt = new Date();
  }

  reactivate(): void {
    if (this.props.status === 'revoked') return;
    this.props.status = 'active';
    this.props.deprecatedAt = undefined;
    this.props.updatedAt = new Date();
  }

  updateLastUsed(): void {
    this.props.lastUsedAt = new Date();
  }

  update(props: Partial<{
    name: string;
    scope: ApiKeyScope;
    tier: ApiKeyTier;
    ipAllowlist: string[];
    rateLimit: number;
    allowedOrigins: string[];
  }>): void {
    if (props.name !== undefined) this.props.name = props.name;
    if (props.scope !== undefined) this.props.scope = props.scope;
    if (props.tier !== undefined) this.props.tier = props.tier;
    if (props.ipAllowlist !== undefined) this.props.ipAllowlist = props.ipAllowlist;
    if (props.rateLimit !== undefined) this.props.rateLimit = props.rateLimit;
    if (props.allowedOrigins !== undefined) this.props.allowedOrigins = props.allowedOrigins;
    this.props.updatedAt = new Date();
  }

  toResponse() {
    return {
      id: this.props.id,
      name: this.props.name,
      prefix: this.props.prefix,
      scope: this.props.scope,
      tier: this.props.tier,
      status: this.props.status,
      rateLimit: this.props.rateLimit,
      ipAllowlist: this.props.ipAllowlist,
      allowedOrigins: this.props.allowedOrigins,
      deprecatedAt: this.props.deprecatedAt?.toISOString(),
      revokedAt: this.props.revokedAt?.toISOString(),
      expiresAt: this.props.expiresAt?.toISOString(),
      lastUsedAt: this.props.lastUsedAt?.toISOString(),
      createdAt: this.props.createdAt.toISOString(),
    };
  }

  toStorage() {
    return {
      ...this.props,
      tenantId: this.props.tenantId.toString(),
      deprecatedAt: this.props.deprecatedAt ?? null,
      revokedAt: this.props.revokedAt ?? null,
      expiresAt: this.props.expiresAt ?? null,
      lastUsedAt: this.props.lastUsedAt ?? null,
    };
  }
}
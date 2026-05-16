import { ulid } from 'ulid';

export enum ApiKeyType {
  PUBLISHABLE = 'publishable',
  SECRET = 'secret',
  SERVICE_ACCOUNT = 'service_account',
  TEMPORARY = 'temporary',
}

export enum ApiKeyEnv {
  LIVE = 'live',
  DEV = 'dev',
  STAGING = 'staging',
}

export enum ApiKeyScope {
  READ = 'read',
  WRITE = 'write',
  ADMIN = 'admin',
  IDENTITY_READ = 'identity:read',
  IDENTITY_WRITE = 'identity:write',
  IDENTITY_ADMIN = 'identity:admin',
  TENANT_READ = 'tenant:read',
  TENANT_WRITE = 'tenant:write',
  TENANT_ADMIN = 'tenant:admin',
  API_READ = 'api:read',
  API_WRITE = 'api:write',
  API_ADMIN = 'api:admin',
  RESOURCE_READ = 'resource:read',
  RESOURCE_WRITE = 'resource:write',
  RESOURCE_DELETE = 'resource:delete',
}

export interface ApiKeyProps {
  id: string;
  ulid: string;
  tenantId: string;
  type: ApiKeyType;
  env: ApiKeyEnv;
  scopes: ApiKeyScope[];
  ipAllowlist: string[];
  domainAllowlist: string[];
  allowedOrigins: string[];
  rateLimit: number;
  monthlyQuota?: number;
  quotaUsed?: number;
  createdAt: Date;
  expiresAt: Date;
  lastUsedAt?: Date;
  lastUsedIp?: string;
  lastUsedUserAgent?: string;
  revokedAt?: Date;
  revokedBy?: string;
  revocationReason?: string;
  metadata: Record<string, unknown>;
  secretHash?: string;
  projectId?: string;
  serviceAccountId?: string;
  tags: string[];
  rotationScheduledAt?: Date;
  rotatedAt?: Date;
  rotationFrequencyDays?: number;
  previousKeyId?: string;
}

export class ApiKeyEntity {
  private props: ApiKeyProps;

  constructor(props: ApiKeyProps) {
    this.props = props;
  }

  get id(): string { return this.props.id; }
  get ulid(): string { return this.props.ulid; }
  get tenantId(): string { return this.props.tenantId; }
  get type(): ApiKeyType { return this.props.type; }
  get env(): ApiKeyEnv { return this.props.env; }
  get scopes(): ApiKeyScope[] { return this.props.scopes; }
  get ipAllowlist(): string[] { return this.props.ipAllowlist; }
  get domainAllowlist(): string[] { return this.props.domainAllowlist || []; }
  get allowedOrigins(): string[] { return this.props.allowedOrigins || []; }
  get rateLimit(): number { return this.props.rateLimit; }
  get monthlyQuota(): number | undefined { return this.props.monthlyQuota; }
  get quotaUsed(): number | undefined { return this.props.quotaUsed; }
  get metadata(): Record<string, unknown> { return this.props.metadata; }
  get createdAt(): Date { return this.props.createdAt; }
  get expiresAt(): Date { return this.props.expiresAt; }
  get lastUsedAt(): Date | undefined { return this.props.lastUsedAt; }
  get lastUsedIp(): string | undefined { return this.props.lastUsedIp; }
  get lastUsedUserAgent(): string | undefined { return this.props.lastUsedUserAgent; }
  get tags(): string[] { return this.props.tags || []; }
  get isExpired(): boolean { return new Date() > this.props.expiresAt; }
  get isRevoked(): boolean { return !!this.props.revokedAt; }
  get isActive(): boolean { return !this.isExpired && !this.isRevoked; }
  get isServiceAccount(): boolean { return this.props.type === ApiKeyType.SERVICE_ACCOUNT; }
  get isTemporary(): boolean { return this.props.type === ApiKeyType.TEMPORARY; }
  get isLive(): boolean { return this.props.env === ApiKeyEnv.LIVE; }
  get isExhausted(): boolean {
    return this.props.monthlyQuota !== undefined &&
           this.props.quotaUsed !== undefined &&
           this.props.quotaUsed >= this.props.monthlyQuota;
  }

  hasScope(requiredScope: ApiKeyScope | string): boolean {
    if (this.props.scopes.includes(ApiKeyScope.ADMIN as any)) return true;
    return this.props.scopes.includes(requiredScope as ApiKeyScope);
  }

  isIpAllowed(ip: string): boolean {
    if (this.props.ipAllowlist.length === 0) return true;
    return this.props.ipAllowlist.some(cidr => this.cidrMatch(ip, cidr));
  }

  isDomainAllowed(domain: string): boolean {
    const allowlist = this.props.domainAllowlist || [];
    if (allowlist.length === 0) return true;
    return allowlist.some(allowed => domain === allowed || domain.endsWith(`.${allowed}`));
  }

  isOriginAllowed(origin: string): boolean {
    const origins = this.props.allowedOrigins || [];
    if (origins.length === 0) return true;
    return origins.includes(origin);
  }

  recordUsage(ip?: string, userAgent?: string): void {
    this.props.lastUsedAt = new Date();
    if (ip) this.props.lastUsedIp = ip;
    if (userAgent) this.props.lastUsedUserAgent = userAgent;
    if (this.props.quotaUsed !== undefined) this.props.quotaUsed += 1;
  }

  revoke(revokedBy?: string, reason?: string): void {
    this.props.revokedAt = new Date();
    this.props.revokedBy = revokedBy;
    this.props.revocationReason = reason;
  }

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

  private ipToInt(ip: string): number {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  }

  rotate(newUlid: string, newSecretHash?: string): ApiKeyEntity {
    return new ApiKeyEntity({
      ...this.props,
      id: ulid(),
      ulid: newUlid,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
      secretHash: newSecretHash,
      revokedAt: undefined,
      metadata: { ...this.props.metadata },
    });
  }

  toResponse() {
    return {
      id: this.props.id,
      ulid: this.props.ulid,
      type: this.props.type,
      env: this.props.env,
      scopes: this.props.scopes,
      rateLimit: this.props.rateLimit,
      createdAt: this.props.createdAt.toISOString(),
      expiresAt: this.props.expiresAt.toISOString(),
      isActive: this.isActive,
      metadata: this.props.metadata,
    };
  }
}
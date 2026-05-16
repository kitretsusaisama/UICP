import { ulid } from 'ulid';
import { ApiKeyType, ApiKeyEnv } from '../api-key.entity';

export interface PlatformApiKeyProps {
  id: string;
  ulid: string;
  platformIdentityId: string;
  type: ApiKeyType;
  env: ApiKeyEnv;
  scopes: string[];
  ipAllowlist: string[];
  rateLimit: number;
  createdAt: Date;
  expiresAt: Date;
  revokedAt?: Date;
  lastUsedAt?: Date;
  lastUsedIp?: string;
  metadata: Record<string, unknown>;
  secretHash?: string;
}

export class PlatformApiKeyEntity {
  private props: PlatformApiKeyProps;

  constructor(props: PlatformApiKeyProps) {
    this.props = props;
  }

  get id(): string { return this.props.id; }
  get ulid(): string { return this.props.ulid; }
  get platformIdentityId(): string { return this.props.platformIdentityId; }
  get type(): ApiKeyType { return this.props.type; }
  get env(): ApiKeyEnv { return this.props.env; }
  get scopes(): string[] { return this.props.scopes; }
  get ipAllowlist(): string[] { return this.props.ipAllowlist; }
  get rateLimit(): number { return this.props.rateLimit; }
  get metadata(): Record<string, unknown> { return this.props.metadata; }
  get createdAt(): Date { return this.props.createdAt; }
  get expiresAt(): Date { return this.props.expiresAt; }
  get lastUsedAt(): Date | undefined { return this.props.lastUsedAt; }
  get lastUsedIp(): string | undefined { return this.props.lastUsedIp; }
  get isExpired(): boolean { return new Date() > this.props.expiresAt; }
  get isRevoked(): boolean { return !!this.props.revokedAt; }
  get isActive(): boolean { return !this.isExpired && !this.isRevoked; }

  hasScope(scope: string): boolean {
    return this.props.scopes.includes(scope) || this.props.scopes.includes('admin');
  }

  recordUsage(ip: string): void {
    this.props.lastUsedAt = new Date();
    this.props.lastUsedIp = ip;
  }

  revoke(): void {
    this.props.revokedAt = new Date();
  }

  rotate(newUlid: string, newSecretHash?: string): PlatformApiKeyEntity {
    return new PlatformApiKeyEntity({
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
      lastUsedAt: this.props.lastUsedAt?.toISOString() ?? null,
      isActive: this.isActive,
      metadata: this.props.metadata,
    };
  }

  static create(props: Partial<PlatformApiKeyProps> & {
    platformIdentityId: string;
    type: ApiKeyType;
    env: ApiKeyEnv;
    scopes: string[];
  }): PlatformApiKeyEntity {
    return new PlatformApiKeyEntity({
      id: props.id ?? ulid(),
      ulid: props.ulid ?? ulid(),
      platformIdentityId: props.platformIdentityId,
      type: props.type,
      env: props.env,
      scopes: props.scopes,
      ipAllowlist: props.ipAllowlist ?? [],
      rateLimit: props.rateLimit ?? 10000,
      createdAt: props.createdAt ?? new Date(),
      expiresAt: props.expiresAt ?? new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
      revokedAt: props.revokedAt,
      lastUsedAt: props.lastUsedAt,
      lastUsedIp: props.lastUsedIp,
      metadata: props.metadata ?? {},
      secretHash: props.secretHash,
    });
  }
}
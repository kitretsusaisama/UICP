import { ulid } from 'ulid';

export enum ApiKeyType {
  PUBLISHABLE = 'publishable',
  SECRET = 'secret',
}

export enum ApiKeyEnv {
  LIVE = 'live',
  DEV = 'dev',
}

export enum ApiKeyScope {
  READ = 'read',
  WRITE = 'write',
  ADMIN = 'admin',
}

export interface ApiKeyProps {
  id: string;
  ulid: string;
  tenantId: string;
  type: ApiKeyType;
  env: ApiKeyEnv;
  scopes: ApiKeyScope[];
  ipAllowlist: string[];
  rateLimit: number;
  createdAt: Date;
  expiresAt: Date;
  revokedAt?: Date;
  metadata: Record<string, unknown>;
  secretHash?: string;
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
  get rateLimit(): number { return this.props.rateLimit; }
  get metadata(): Record<string, unknown> { return this.props.metadata; }
  get createdAt(): Date { return this.props.createdAt; }
  get expiresAt(): Date { return this.props.expiresAt; }
  get isExpired(): boolean { return new Date() > this.props.expiresAt; }
  get isRevoked(): boolean { return !!this.props.revokedAt; }
  get isActive(): boolean { return !this.isExpired && !this.isRevoked; }

  revoke(): void {
    this.props.revokedAt = new Date();
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
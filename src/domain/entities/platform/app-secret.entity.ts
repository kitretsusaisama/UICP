export type SecretStatus = 'active' | 'deprecated' | 'revoked';

export interface AppSecretProps {
  appId: string;
  tenantId: string;
  secretHash: string;
  status: SecretStatus;
  createdAt?: Date;
  expiresAt?: Date | null;
}

export class AppSecret {
  readonly appId: string;
  readonly tenantId: string;
  readonly secretHash: string;
  private _status: SecretStatus;
  readonly createdAt: Date;
  private _expiresAt: Date | null;

  constructor(props: AppSecretProps) {
    this.appId = props.appId;
    this.tenantId = props.tenantId;
    this.secretHash = props.secretHash;
    this._status = props.status;
    this.createdAt = props.createdAt ?? new Date();
    this._expiresAt = props.expiresAt ?? null;
  }

  get status(): SecretStatus {
    return this._status;
  }

  get expiresAt(): Date | null {
    return this._expiresAt;
  }

  isActive(): boolean {
    if (this._status === 'revoked') return false;
    if (this._expiresAt && this._expiresAt < new Date()) {
      this._status = 'revoked'; // Lazy evaluation revocation
      return false;
    }
    return true;
  }

  deprecate(gracePeriodSeconds = 3600): void {
    if (this._status === 'revoked') return;
    this._status = 'deprecated';
    this._expiresAt = new Date(Date.now() + gracePeriodSeconds * 1000);
  }

  revoke(): void {
    this._status = 'revoked';
    this._expiresAt = new Date();
  }
}

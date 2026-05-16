import { ulid } from 'ulid';
import { PlatformRoleType } from './platform-role.entity';

export enum PlatformIdentityStatus {
  ACTIVE = 'active',
  SUSPENDED = 'suspended',
  DEACTIVATED = 'deactivated',
  PENDING = 'pending',
}

export enum MfaType {
  TOTP = 'totp',
  WEBAUTHN = 'webauthn',
  EMAIL = 'email',
  PASSKEY = 'passkey',
}

export interface PlatformIdentityProps {
  id: string;
  email: string;
  displayName: string;
  passwordHash?: string;
  mfaType: MfaType;
  mfaSecret?: string;
  mfaEnabled: boolean;
  status: PlatformIdentityStatus;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  lastLoginAt?: Date;
  lastLoginIp?: string;
  lastLoginDevice?: string;
  createdAt: Date;
  updatedAt: Date;
}

export class PlatformIdentity {
  readonly id: string;
  readonly email: string;
  readonly displayName: string;
  private _passwordHash: string | null;
  private _mfaType: MfaType;
  private _mfaSecret: string | null;
  private _mfaEnabled: boolean;
  private _status: PlatformIdentityStatus;
  private _riskScore: number;
  private _riskLevel: 'low' | 'medium' | 'high' | 'critical';
  private _lastLoginAt: Date | null;
  private _lastLoginIp: string | null;
  private _lastLoginDevice: string | null;
  readonly createdAt: Date;
  private _updatedAt: Date;

  constructor(props: PlatformIdentityProps) {
    this.id = props.id;
    this.email = props.email;
    this.displayName = props.displayName;
    this._passwordHash = props.passwordHash ?? null;
    this._mfaType = props.mfaType;
    this._mfaSecret = props.mfaSecret ?? null;
    this._mfaEnabled = props.mfaEnabled;
    this._status = props.status;
    this._riskScore = props.riskScore;
    this._riskLevel = props.riskLevel;
    this._lastLoginAt = props.lastLoginAt ?? null;
    this._lastLoginIp = props.lastLoginIp ?? null;
    this._lastLoginDevice = props.lastLoginDevice ?? null;
    this.createdAt = props.createdAt;
    this._updatedAt = props.updatedAt;
  }

  get passwordHash(): string | null { return this._passwordHash; }
  get mfaType(): MfaType { return this._mfaType; }
  get mfaSecret(): string | null { return this._mfaSecret; }
  get mfaEnabled(): boolean { return this._mfaEnabled; }
  get status(): PlatformIdentityStatus { return this._status; }
  get riskScore(): number { return this._riskScore; }
  get riskLevel(): 'low' | 'medium' | 'high' | 'critical' { return this._riskLevel; }
  get lastLoginAt(): Date | null { return this._lastLoginAt; }
  get lastLoginIp(): string | null { return this._lastLoginIp; }
  get lastLoginDevice(): string | null { return this._lastLoginDevice; }
  get updatedAt(): Date { return this._updatedAt; }

  get isActive(): boolean { return this._status === PlatformIdentityStatus.ACTIVE; }
  get isSuspended(): boolean { return this._status === PlatformIdentityStatus.SUSPENDED; }
  get requiresStepUp(): boolean { return this._riskScore > 0.7; }
  get shouldAutoSuspend(): boolean { return this._riskScore > 0.85; }

  updateLastLogin(ip: string, device: string): void {
    this._lastLoginAt = new Date();
    this._lastLoginIp = ip;
    this._lastLoginDevice = device;
    this._updatedAt = new Date();
  }

  updateMfa(secret: string, type: MfaType): void {
    this._mfaSecret = secret;
    this._mfaType = type;
    this._mfaEnabled = true;
    this._updatedAt = new Date();
  }

  updateRiskScore(score: number, level: 'low' | 'medium' | 'high' | 'critical'): void {
    this._riskScore = score;
    this._riskLevel = level;
    this._updatedAt = new Date();

    if (score > 0.85 && this._status === PlatformIdentityStatus.ACTIVE) {
      this.suspend('Risk score exceeded auto-suspend threshold (>0.85)');
    }
  }

  suspend(reason: string): void {
    this._status = PlatformIdentityStatus.SUSPENDED;
    this._updatedAt = new Date();
  }

  reactivate(): void {
    this._status = PlatformIdentityStatus.ACTIVE;
    this._riskScore = 0;
    this._riskLevel = 'low';
    this._updatedAt = new Date();
  }

  deactivate(): void {
    this._status = PlatformIdentityStatus.DEACTIVATED;
    this._updatedAt = new Date();
  }

  setPassword(hash: string): void {
    this._passwordHash = hash;
    this._updatedAt = new Date();
  }

  toResponse() {
    return {
      id: this.id,
      email: this.email,
      displayName: this.displayName,
      status: this._status,
      mfaEnabled: this._mfaEnabled,
      riskScore: this._riskScore,
      riskLevel: this._riskLevel,
      lastLoginAt: this._lastLoginAt?.toISOString() ?? null,
      createdAt: this.createdAt.toISOString(),
    };
  }

  static create(props: Partial<PlatformIdentityProps> & { email: string; displayName: string }): PlatformIdentity {
    return new PlatformIdentity({
      id: props.id ?? ulid(),
      email: props.email,
      displayName: props.displayName,
      passwordHash: props.passwordHash,
      mfaType: props.mfaType ?? MfaType.TOTP,
      mfaSecret: props.mfaSecret,
      mfaEnabled: props.mfaEnabled ?? false,
      status: props.status ?? PlatformIdentityStatus.PENDING,
      riskScore: props.riskScore ?? 0,
      riskLevel: props.riskLevel ?? 'low',
      lastLoginAt: props.lastLoginAt,
      lastLoginIp: props.lastLoginIp,
      lastLoginDevice: props.lastLoginDevice,
      createdAt: props.createdAt ?? new Date(),
      updatedAt: props.updatedAt ?? new Date(),
    });
  }
}
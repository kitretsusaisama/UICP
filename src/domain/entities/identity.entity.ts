import { IdentityId } from '../value-objects/identity-id.vo';
import { TenantId } from '../value-objects/tenant-id.vo';
import { UserId } from '../value-objects/user-id.vo';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

export type IdentityType = 'EMAIL' | 'PHONE' | 'OAUTH_GOOGLE' | 'OAUTH_GITHUB' | 'OAUTH_APPLE' | 'OAUTH_MICROSOFT';

/** Opaque wrapper for an AES-256-GCM encrypted value (base64(iv).base64(tag).base64(ciphertext).kid). */
export type EncryptedValue = string & { readonly __brand: 'EncryptedValue' };

export function toEncryptedValue(raw: string): EncryptedValue {
  return raw as EncryptedValue;
}

export interface CreateEmailIdentityParams {
  id: IdentityId;
  tenantId: TenantId;
  userId: UserId;
  valueEnc: EncryptedValue;
  valueHash: string;
  createdAt?: Date;
}

export interface CreatePhoneIdentityParams {
  id: IdentityId;
  tenantId: TenantId;
  userId: UserId;
  valueEnc: EncryptedValue;
  valueHash: string;
  createdAt?: Date;
}

export interface CreateOAuthIdentityParams {
  id: IdentityId;
  tenantId: TenantId;
  userId: UserId;
  type: IdentityType;
  valueEnc: EncryptedValue;
  valueHash: string;
  providerSub: string;
  providerDataEnc?: EncryptedValue;
  /** OAuth identities are pre-verified by the provider. */
  verified?: boolean;
  verifiedAt?: Date;
  createdAt?: Date;
}

export interface ReconstitutedIdentityParams {
  id: IdentityId;
  tenantId: TenantId;
  userId: UserId;
  type: IdentityType;
  valueEnc: EncryptedValue;
  valueHash: string;
  providerSub?: string;
  providerDataEnc?: EncryptedValue;
  verified: boolean;
  verifiedAt?: Date;
  createdAt: Date;
}

/**
 * Identity entity — represents a verifiable credential link (email, phone, or OAuth provider)
 * within the User aggregate. Pure domain object; zero framework imports.
 */
export class Identity {
  readonly id: IdentityId;
  readonly tenantId: TenantId;
  readonly userId: UserId;
  readonly type: IdentityType;
  private valueEnc: EncryptedValue;
  private readonly valueHash: string;
  private readonly providerSub?: string;
  private providerDataEnc?: EncryptedValue;
  private verified: boolean;
  private verifiedAt?: Date;
  readonly createdAt: Date;

  private constructor(params: ReconstitutedIdentityParams) {
    this.id = params.id;
    this.tenantId = params.tenantId;
    this.userId = params.userId;
    this.type = params.type;
    this.valueEnc = params.valueEnc;
    this.valueHash = params.valueHash;
    this.providerSub = params.providerSub;
    this.providerDataEnc = params.providerDataEnc;
    this.verified = params.verified;
    this.verifiedAt = params.verifiedAt;
    this.createdAt = params.createdAt;
  }

  // ── Factories ──────────────────────────────────────────────────────────────

  static createEmail(params: CreateEmailIdentityParams): Identity {
    return new Identity({
      id: params.id,
      tenantId: params.tenantId,
      userId: params.userId,
      type: 'EMAIL',
      valueEnc: params.valueEnc,
      valueHash: params.valueHash,
      verified: false,
      createdAt: params.createdAt ?? new Date(),
    });
  }

  static createPhone(params: CreatePhoneIdentityParams): Identity {
    return new Identity({
      id: params.id,
      tenantId: params.tenantId,
      userId: params.userId,
      type: 'PHONE',
      valueEnc: params.valueEnc,
      valueHash: params.valueHash,
      verified: false,
      createdAt: params.createdAt ?? new Date(),
    });
  }

  static createOAuth(params: CreateOAuthIdentityParams): Identity {
    const now = params.createdAt ?? new Date();
    const isVerified = params.verified ?? true;
    return new Identity({
      id: params.id,
      tenantId: params.tenantId,
      userId: params.userId,
      type: params.type,
      valueEnc: params.valueEnc,
      valueHash: params.valueHash,
      providerSub: params.providerSub,
      providerDataEnc: params.providerDataEnc,
      verified: isVerified,
      verifiedAt: isVerified ? (params.verifiedAt ?? now) : undefined,
      createdAt: now,
    });
  }

  /** Reconstitute from persistence (no invariant checks — data already validated). */
  static reconstitute(params: ReconstitutedIdentityParams): Identity {
    return new Identity(params);
  }

  // ── Mutations ──────────────────────────────────────────────────────────────

  /**
   * Mark this identity as verified.
   * @throws DomainException(IDENTITY_ALREADY_VERIFIED) if already verified.
   */
  verify(): void {
    if (this.verified) {
      throw new DomainException(
        DomainErrorCode.IDENTITY_ALREADY_VERIFIED,
        `Identity ${this.id.toString()} is already verified`,
      );
    }
    this.verified = true;
    this.verifiedAt = new Date();
  }

  updateProviderData(data: EncryptedValue): void {
    this.providerDataEnc = data;
  }

  // ── Queries ────────────────────────────────────────────────────────────────

  isVerified(): boolean {
    return this.verified;
  }

  getValueHash(): string {
    return this.valueHash;
  }

  getType(): IdentityType {
    return this.type;
  }

  getValueEnc(): EncryptedValue {
    return this.valueEnc;
  }

  getProviderSub(): string | undefined {
    return this.providerSub;
  }

  getProviderDataEnc(): EncryptedValue | undefined {
    return this.providerDataEnc;
  }

  getVerifiedAt(): Date | undefined {
    return this.verifiedAt;
  }
}

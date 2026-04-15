import { SessionId } from '../value-objects/session-id.vo';
import { TenantId } from '../value-objects/tenant-id.vo';
import { UserId } from '../value-objects/user-id.vo';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';
import { SessionCreatedEvent, SessionRevokedEvent, SessionDomainEvent } from '../events/session.events';

export type SessionStatus = 'CREATED' | 'MFA_PENDING' | 'ACTIVE' | 'EXPIRED' | 'REVOKED';

export interface CreateSessionParams {
  id?: SessionId;
  tenantId: TenantId;
  userId: UserId;
  principalId?: string;
  membershipId?: string;
  actorId?: string;
  policyVersion?: string;
  manifestVersion?: string;
  recentAuthAt?: Date;
  /** HMAC of the client IP address (never store raw IP). */
  ipHash: string;
  uaBrowser: string;
  uaOs: string;
  uaDeviceType: string;
  deviceFingerprint?: string;
  /** Session TTL in seconds (default: 86400). */
  ttlSeconds?: number;
  createdAt?: Date;
}

/**
 * Session aggregate — represents an authenticated session stored in Redis.
 *
 * State machine:
 *   CREATED ──[requireMfa]──────► MFA_PENDING
 *   CREATED ──[no MFA needed]──► ACTIVE  (caller sets status directly via create())
 *   MFA_PENDING ──[verifyMfa]──► ACTIVE
 *   MFA_PENDING ──[TTL elapsed]► EXPIRED
 *   ACTIVE ──[TTL elapsed]─────► EXPIRED
 *   ACTIVE ──[revoke]──────────► REVOKED
 *   REVOKED / EXPIRED: terminal
 */
export class Session {
  readonly id: SessionId;
  readonly tenantId: TenantId;
  readonly userId: UserId;
  readonly principalId: string;
  readonly membershipId?: string;
  readonly actorId?: string;
  readonly policyVersion?: string;
  readonly manifestVersion?: string;
  private _status: SessionStatus;
  private _mfaVerified: boolean;
  private _recentAuthAt?: Date;
  private _mfaVerifiedAt?: Date;
  readonly ipHash: string;
  readonly uaBrowser: string;
  readonly uaOs: string;
  readonly uaDeviceType: string;
  readonly deviceFingerprint?: string;
  readonly createdAt: Date;
  private _expiresAt: Date;
  private _revokedAt?: Date;
  private _revokedReason?: string;

  private readonly _domainEvents: SessionDomainEvent[] = [];

  private constructor(params: {
    id: SessionId;
    tenantId: TenantId;
    userId: UserId;
    principalId: string;
    membershipId?: string;
    actorId?: string;
    policyVersion?: string;
    manifestVersion?: string;
    status: SessionStatus;
    mfaVerified: boolean;
    recentAuthAt?: Date;
    mfaVerifiedAt?: Date;
    ipHash: string;
    uaBrowser: string;
    uaOs: string;
    uaDeviceType: string;
    deviceFingerprint?: string;
    createdAt: Date;
    expiresAt: Date;
    revokedAt?: Date;
    revokedReason?: string;
  }) {
    this.id = params.id;
    this.tenantId = params.tenantId;
    this.userId = params.userId;
    this.principalId = params.principalId;
    this.membershipId = params.membershipId;
    this.actorId = params.actorId;
    this.policyVersion = params.policyVersion;
    this.manifestVersion = params.manifestVersion;
    this._status = params.status;
    this._mfaVerified = params.mfaVerified;
    this._recentAuthAt = params.recentAuthAt;
    this._mfaVerifiedAt = params.mfaVerifiedAt;
    this.ipHash = params.ipHash;
    this.uaBrowser = params.uaBrowser;
    this.uaOs = params.uaOs;
    this.uaDeviceType = params.uaDeviceType;
    this.deviceFingerprint = params.deviceFingerprint;
    this.createdAt = params.createdAt;
    this._expiresAt = params.expiresAt;
    this._revokedAt = params.revokedAt;
    this._revokedReason = params.revokedReason;
  }

  // ── Factory ────────────────────────────────────────────────────────────────

  /**
   * Create a new session in CREATED status.
   * Raises: SessionCreatedEvent
   */
  static create(params: CreateSessionParams): Session {
    const now = params.createdAt ?? new Date();
    const ttl = params.ttlSeconds ?? 86400;
    const expiresAt = new Date(now.getTime() + ttl * 1000);
    const id = params.id ?? SessionId.create();

    const session = new Session({
      id,
      tenantId: params.tenantId,
      userId: params.userId,
      principalId: params.principalId ?? params.userId.toString(),
      membershipId: params.membershipId,
      actorId: params.actorId,
      policyVersion: params.policyVersion,
      manifestVersion: params.manifestVersion,
      status: 'CREATED',
      mfaVerified: false,
      recentAuthAt: params.recentAuthAt,
      ipHash: params.ipHash,
      uaBrowser: params.uaBrowser,
      uaOs: params.uaOs,
      uaDeviceType: params.uaDeviceType,
      deviceFingerprint: params.deviceFingerprint,
      createdAt: now,
      expiresAt,
    });

    session._domainEvents.push(
      new SessionCreatedEvent(
        {
          sessionId: id.toString(),
          userId: params.userId.toString(),
          ipHash: params.ipHash,
          uaBrowser: params.uaBrowser,
        },
        params.tenantId.toString(),
        1,
      ),
    );

    return session;
  }

  /** Reconstitute from persistence. */
  static reconstitute(params: {
    id: SessionId;
    tenantId: TenantId;
    userId: UserId;
    principalId: string;
    membershipId?: string;
    actorId?: string;
    policyVersion?: string;
    manifestVersion?: string;
    status: SessionStatus;
    mfaVerified: boolean;
    recentAuthAt?: Date;
    mfaVerifiedAt?: Date;
    ipHash: string;
    uaBrowser: string;
    uaOs: string;
    uaDeviceType: string;
    deviceFingerprint?: string;
    createdAt: Date;
    expiresAt: Date;
    revokedAt?: Date;
    revokedReason?: string;
  }): Session {
    return new Session(params);
  }

  // ── Commands ───────────────────────────────────────────────────────────────

  /**
   * Transition CREATED → MFA_PENDING.
   * @throws DomainException(INVALID_SESSION_TRANSITION) if not CREATED.
   */
  requireMfa(): void {
    if (this._status !== 'CREATED') {
      throw new DomainException(
        DomainErrorCode.INVALID_SESSION_TRANSITION,
        `Cannot require MFA in session status ${this._status}`,
      );
    }
    this._status = 'MFA_PENDING';
  }

  /**
   * Transition MFA_PENDING → ACTIVE.
   * @throws DomainException(INVALID_SESSION_TRANSITION) if not MFA_PENDING.
   */
  verifyMfa(): void {
    if (this._status !== 'MFA_PENDING') {
      throw new DomainException(
        DomainErrorCode.INVALID_SESSION_TRANSITION,
        `Cannot verify MFA in session status ${this._status}`,
      );
    }
    const now = new Date();
    this._status = 'ACTIVE';
    this._mfaVerified = true;
    this._recentAuthAt = now;
    this._mfaVerifiedAt = now;
  }

  /**
   * Revoke the session (terminal).
   * @throws DomainException(SESSION_ALREADY_TERMINATED) if already REVOKED or EXPIRED.
   */
  revoke(reason: string): void {
    if (this._status === 'REVOKED' || this._status === 'EXPIRED') {
      throw new DomainException(
        DomainErrorCode.SESSION_ALREADY_TERMINATED,
        `Session is already ${this._status.toLowerCase()}`,
      );
    }

    const now = new Date();
    this._status = 'REVOKED';
    this._revokedAt = now;
    this._revokedReason = reason;

    this._domainEvents.push(
      new SessionRevokedEvent(
        {
          sessionId: this.id.toString(),
          reason,
          revokedAt: now.toISOString(),
        },
        this.tenantId.toString(),
        2,
      ),
    );
  }

  /**
   * Extend the session TTL by the given number of seconds (sliding TTL).
   * No-op if the session is already terminated.
   */
  extendTtl(seconds: number): void {
    if (this._status === 'REVOKED' || this._status === 'EXPIRED') return;
    this._expiresAt = new Date(Date.now() + seconds * 1000);
  }

  // ── Queries ────────────────────────────────────────────────────────────────

  isExpired(): boolean {
    return this._status === 'EXPIRED' || (this._status !== 'REVOKED' && new Date() > this._expiresAt);
  }

  isActive(): boolean {
    return this._status === 'ACTIVE' && !this.isExpired();
  }

  getStatus(): SessionStatus {
    return this._status;
  }

  isMfaVerified(): boolean {
    return this._mfaVerified;
  }

  getMfaVerifiedAt(): Date | undefined {
    return this._mfaVerifiedAt;
  }

  getRecentAuthAt(): Date | undefined {
    return this._recentAuthAt;
  }

  getExpiresAt(): Date {
    return this._expiresAt;
  }

  getRevokedAt(): Date | undefined {
    return this._revokedAt;
  }

  getRevokedReason(): string | undefined {
    return this._revokedReason;
  }

  pullDomainEvents(): SessionDomainEvent[] {
    const events = [...this._domainEvents];
    this._domainEvents.length = 0;
    return events;
  }
}

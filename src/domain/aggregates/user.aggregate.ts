import { UserId } from '../value-objects/user-id.vo';
import { TenantId } from '../value-objects/tenant-id.vo';
import { IdentityId } from '../value-objects/identity-id.vo';
import { Email } from '../value-objects/email.vo';
import { PhoneNumber } from '../value-objects/phone-number.vo';
import { Identity, IdentityType, EncryptedValue, toEncryptedValue } from '../entities/identity.entity';
import { Credential } from '../entities/credential.entity';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';
import {
  UserCreatedEvent,
  UserActivatedEvent,
  UserSuspendedEvent,
  UserUnsuspendedEvent,
  UserDeletedEvent,
  IdentityLinkedEvent,
  IdentityVerifiedEvent,
  PasswordChangedEvent,
  UserDomainEvent,
} from '../events/user.events';

export type UserStatus = 'PENDING' | 'ACTIVE' | 'SUSPENDED' | 'DELETED';

const MAX_IDENTITIES_PER_TYPE = 3;

export interface CreateWithEmailParams {
  email: Email;
  tenantId: TenantId;
  /** Pre-encrypted email value (provided by infrastructure layer). */
  emailEnc: EncryptedValue;
  /** HMAC of the email for searchable lookups. */
  emailHash: string;
}

export interface CreateWithPhoneParams {
  phone: PhoneNumber;
  tenantId: TenantId;
  phoneEnc: EncryptedValue;
  phoneHash: string;
}

/**
 * User aggregate root — manages user lifecycle and linked identities.
 *
 * State machine:
 *   PENDING ──[verifyIdentity (first)]──► ACTIVE
 *   ACTIVE  ──[suspend]────────────────► SUSPENDED
 *   SUSPENDED ──[unsuspend]────────────► ACTIVE
 *   ACTIVE | SUSPENDED ──[delete]──────► DELETED
 *   DELETED: terminal — no further transitions
 */
export class User {
  private readonly _id: UserId;
  private readonly _tenantId: TenantId;
  private _status: UserStatus;
  private _displayNameEnc?: EncryptedValue;
  private _identities: Identity[];
  private _credential?: Credential;
  private _suspendUntil?: Date;
  private _metadataEnc?: EncryptedValue;
  /** Optimistic lock counter — incremented on every persisted mutation. */
  private _version: number;
  private readonly _createdAt: Date;
  private _updatedAt: Date;
  /** Uncommitted domain events raised during this session. */
  private readonly _domainEvents: UserDomainEvent[];

  private constructor(params: {
    id: UserId;
    tenantId: TenantId;
    status: UserStatus;
    displayNameEnc?: EncryptedValue;
    identities: Identity[];
    credential?: Credential;
    suspendUntil?: Date;
    metadataEnc?: EncryptedValue;
    version: number;
    createdAt: Date;
    updatedAt: Date;
  }) {
    this._id = params.id;
    this._tenantId = params.tenantId;
    this._status = params.status;
    this._displayNameEnc = params.displayNameEnc;
    this._identities = params.identities;
    this._credential = params.credential;
    this._suspendUntil = params.suspendUntil;
    this._metadataEnc = params.metadataEnc;
    this._version = params.version;
    this._createdAt = params.createdAt;
    this._updatedAt = params.updatedAt;
    this._domainEvents = [];
  }

  // ── Factory Methods ────────────────────────────────────────────────────────

  /**
   * Create a new user with an email identity.
   * Raises: UserCreatedEvent, IdentityLinkedEvent
   */
  static createWithEmail(params: CreateWithEmailParams): User {
    const userId = UserId.create();
    const identityId = IdentityId.create();
    const now = new Date();

    const identity = Identity.createEmail({
      id: identityId,
      tenantId: params.tenantId,
      userId,
      valueEnc: params.emailEnc,
      valueHash: params.emailHash,
      createdAt: now,
    });

    const user = new User({
      id: userId,
      tenantId: params.tenantId,
      status: 'PENDING',
      identities: [identity],
      version: 0,
      createdAt: now,
      updatedAt: now,
    });

    user._domainEvents.push(
      new UserCreatedEvent(
        { userId: userId.toString(), tenantId: params.tenantId.toString(), createdAt: now.toISOString() },
        1,
      ),
      new IdentityLinkedEvent(
        { identityId: identityId.toString(), type: 'EMAIL', userId: userId.toString() },
        params.tenantId.toString(),
        2,
      ),
    );

    return user;
  }

  /**
   * Create a new user with a phone identity.
   * Raises: UserCreatedEvent, IdentityLinkedEvent
   */
  static createWithPhone(params: CreateWithPhoneParams): User {
    const userId = UserId.create();
    const identityId = IdentityId.create();
    const now = new Date();

    const identity = Identity.createPhone({
      id: identityId,
      tenantId: params.tenantId,
      userId,
      valueEnc: params.phoneEnc,
      valueHash: params.phoneHash,
      createdAt: now,
    });

    const user = new User({
      id: userId,
      tenantId: params.tenantId,
      status: 'PENDING',
      identities: [identity],
      version: 0,
      createdAt: now,
      updatedAt: now,
    });

    user._domainEvents.push(
      new UserCreatedEvent(
        { userId: userId.toString(), tenantId: params.tenantId.toString(), createdAt: now.toISOString() },
        1,
      ),
      new IdentityLinkedEvent(
        { identityId: identityId.toString(), type: 'PHONE', userId: userId.toString() },
        params.tenantId.toString(),
        2,
      ),
    );

    return user;
  }

  /**
   * Reconstitute a User aggregate directly from a persistence snapshot.
   * Used by repository adapters — bypasses domain invariant checks since
   * data was already validated when originally persisted.
   */
  static reconstitute(params: {
    id: UserId;
    tenantId: TenantId;
    status: UserStatus;
    identities: Identity[];
    credential?: Credential;
    suspendUntil?: Date;
    version: number;
    createdAt: Date;
    updatedAt: Date;
  }): User {
    return new User({
      id: params.id,
      tenantId: params.tenantId,
      status: params.status,
      identities: params.identities,
      credential: params.credential,
      suspendUntil: params.suspendUntil,
      version: params.version,
      createdAt: params.createdAt,
      updatedAt: params.updatedAt,
    });
  }

  /**
   * Reconstitute a User aggregate from its ordered event history.
   * Events must be sorted by aggregateSeq ASC.
   */
  static fromEvents(events: UserDomainEvent[]): User {
    if (events.length === 0) {
      throw new Error('Cannot reconstitute User from empty event list');
    }

    const first = events[0]!;
    if (first.eventType !== 'UserCreated') {
      throw new Error(`First event must be UserCreated, got ${first.eventType}`);
    }

    const createdPayload = (first as UserCreatedEvent).payload;
    const now = new Date(createdPayload.createdAt);

    const user = new User({
      id: UserId.from(createdPayload.userId),
      tenantId: TenantId.from(createdPayload.tenantId),
      status: 'PENDING',
      identities: [],
      version: events.length,
      createdAt: now,
      updatedAt: now,
    });

    for (const event of events) {
      user._applyEvent(event);
    }

    return user;
  }

  // ── Event Application (for fromEvents replay) ──────────────────────────────

  private _applyEvent(event: UserDomainEvent): void {
    switch (event.eventType) {
      case 'UserCreated':
        // Already handled in fromEvents constructor
        break;

      case 'UserActivated':
        this._status = 'ACTIVE';
        this._updatedAt = new Date(event.payload.activatedAt);
        break;

      case 'UserSuspended':
        this._status = 'SUSPENDED';
        this._suspendUntil = event.payload.until ? new Date(event.payload.until) : undefined;
        this._updatedAt = event.occurredAt;
        break;

      case 'UserUnsuspended':
        this._status = 'ACTIVE';
        this._suspendUntil = undefined;
        this._updatedAt = event.occurredAt;
        break;

      case 'UserDeleted':
        this._status = 'DELETED';
        this._updatedAt = new Date(event.payload.deletedAt);
        break;

      case 'IdentityLinked': {
        // During replay we reconstruct a minimal identity stub.
        // Full identity data is loaded separately by the repository.
        const linked = event.payload;
        const stub = Identity.reconstitute({
          id: IdentityId.from(linked.identityId),
          tenantId: this._tenantId,
          userId: this._id,
          type: linked.type,
          valueEnc: toEncryptedValue(''),
          valueHash: '',
          verified: false,
          createdAt: event.occurredAt,
        });
        this._identities.push(stub);
        this._updatedAt = event.occurredAt;
        break;
      }

      case 'IdentityVerified': {
        const identity = this._identities.find(
          (i) => i.id.toString() === event.payload.identityId,
        );
        if (identity && !identity.isVerified()) {
          identity.verify();
        }
        this._updatedAt = event.occurredAt;
        break;
      }

      case 'PasswordChanged':
        this._updatedAt = new Date(event.payload.changedAt);
        break;
    }
  }

  // ── Commands ───────────────────────────────────────────────────────────────

  /**
   * Transition PENDING → ACTIVE.
   * @throws DomainException(CANNOT_ACTIVATE_WITHOUT_VERIFIED_IDENTITY) if no verified identity.
   * @throws DomainException(INVALID_STATUS_TRANSITION) if not PENDING.
   */
  activate(): void {
    if (this._status !== 'PENDING') {
      throw new DomainException(
        DomainErrorCode.INVALID_STATUS_TRANSITION,
        `Cannot activate user in status ${this._status}`,
      );
    }

    const hasVerified = this._identities.some((i) => i.isVerified());
    if (!hasVerified) {
      throw new DomainException(
        DomainErrorCode.CANNOT_ACTIVATE_WITHOUT_VERIFIED_IDENTITY,
        'User must have at least one verified identity before activation',
      );
    }

    const now = new Date();
    this._status = 'ACTIVE';
    this._updatedAt = now;

    this._domainEvents.push(
      new UserActivatedEvent(
        { userId: this._id.toString(), activatedAt: now.toISOString() },
        this._tenantId.toString(),
        this._nextSeq(),
      ),
    );
  }

  /**
   * Transition ACTIVE → SUSPENDED.
   * @throws DomainException(INVALID_STATUS_TRANSITION) if not ACTIVE.
   */
  suspend(reason: string, until?: Date): void {
    if (this._status !== 'ACTIVE') {
      throw new DomainException(
        DomainErrorCode.INVALID_STATUS_TRANSITION,
        `Cannot suspend user in status ${this._status}`,
      );
    }

    this._status = 'SUSPENDED';
    this._suspendUntil = until;
    this._updatedAt = new Date();

    this._domainEvents.push(
      new UserSuspendedEvent(
        { userId: this._id.toString(), reason, until: until?.toISOString() },
        this._tenantId.toString(),
        this._nextSeq(),
      ),
    );
  }

  /**
   * Transition SUSPENDED → ACTIVE.
   * @throws DomainException(INVALID_STATUS_TRANSITION) if not SUSPENDED.
   */
  unsuspend(): void {
    if (this._status !== 'SUSPENDED') {
      throw new DomainException(
        DomainErrorCode.INVALID_STATUS_TRANSITION,
        `Cannot unsuspend user in status ${this._status}`,
      );
    }

    this._status = 'ACTIVE';
    this._suspendUntil = undefined;
    this._updatedAt = new Date();

    this._domainEvents.push(
      new UserUnsuspendedEvent(
        { userId: this._id.toString() },
        this._tenantId.toString(),
        this._nextSeq(),
      ),
    );
  }

  /**
   * Transition any non-DELETED status → DELETED (terminal).
   * @throws DomainException(INVALID_STATUS_TRANSITION) if already DELETED.
   */
  delete(): void {
    if (this._status === 'DELETED') {
      throw new DomainException(
        DomainErrorCode.INVALID_STATUS_TRANSITION,
        'User is already deleted',
      );
    }

    const now = new Date();
    this._status = 'DELETED';
    this._updatedAt = now;

    this._domainEvents.push(
      new UserDeletedEvent(
        { userId: this._id.toString(), deletedAt: now.toISOString() },
        this._tenantId.toString(),
        this._nextSeq(),
      ),
    );
  }

  /**
   * Link a new identity to this user.
   * @throws DomainException(MAX_IDENTITIES_PER_TYPE_EXCEEDED) if ≥3 of same type.
   * @throws DomainException(IDENTITY_ALREADY_LINKED) if duplicate valueHash+type.
   */
  linkIdentity(identity: Identity): void {
    const sameType = this._identities.filter((i) => i.getType() === identity.getType());
    if (sameType.length >= MAX_IDENTITIES_PER_TYPE) {
      throw new DomainException(
        DomainErrorCode.MAX_IDENTITIES_PER_TYPE_EXCEEDED,
        `Maximum of ${MAX_IDENTITIES_PER_TYPE} identities of type ${identity.getType()} allowed`,
      );
    }

    const duplicate = this._identities.some(
      (i) => i.getType() === identity.getType() && i.getValueHash() === identity.getValueHash(),
    );
    if (duplicate) {
      throw new DomainException(
        DomainErrorCode.IDENTITY_ALREADY_LINKED,
        `Identity with this value is already linked to the user`,
      );
    }

    this._identities.push(identity);
    this._updatedAt = new Date();

    this._domainEvents.push(
      new IdentityLinkedEvent(
        {
          identityId: identity.id.toString(),
          type: identity.getType(),
          userId: this._id.toString(),
        },
        this._tenantId.toString(),
        this._nextSeq(),
      ),
    );
  }

  /**
   * Mark an identity as verified. If this is the first verified identity and the
   * user is PENDING, automatically activates the user.
   * @throws DomainException(IDENTITY_NOT_FOUND) if identity not found.
   */
  verifyIdentity(identityId: IdentityId): void {
    const identity = this._identities.find((i) => i.id.equals(identityId));
    if (!identity) {
      throw new DomainException(
        DomainErrorCode.IDENTITY_NOT_FOUND,
        `Identity ${identityId.toString()} not found on user ${this._id.toString()}`,
      );
    }

    // identity.verify() throws IDENTITY_ALREADY_VERIFIED if already verified
    identity.verify();

    const now = new Date();
    this._updatedAt = now;

    this._domainEvents.push(
      new IdentityVerifiedEvent(
        {
          identityId: identityId.toString(),
          type: identity.getType(),
          verifiedAt: now.toISOString(),
        },
        this._id.toString(),
        this._tenantId.toString(),
        this._nextSeq(),
      ),
    );

    // Auto-activate when first identity is verified and user is still PENDING
    if (this._status === 'PENDING') {
      this.activate();
    }
  }

  /**
   * Update the user's credential (hashed password).
   * @throws DomainException(INVALID_STATUS_TRANSITION) if user is DELETED.
   */
  changePassword(newCredential: Credential): void {
    if (this._status === 'DELETED') {
      throw new DomainException(
        DomainErrorCode.INVALID_STATUS_TRANSITION,
        'Cannot change password of a deleted user',
      );
    }

    this._credential = newCredential;
    const now = new Date();
    this._updatedAt = now;

    this._domainEvents.push(
      new PasswordChangedEvent(
        {
          userId: this._id.toString(),
          algorithm: newCredential.algorithm,
          changedAt: now.toISOString(),
        },
        this._tenantId.toString(),
        this._nextSeq(),
      ),
    );
  }

  /**
   * Returns all uncommitted domain events and clears the internal buffer.
   * Call this after persisting the aggregate to collect events for the outbox.
   */
  pullDomainEvents(): UserDomainEvent[] {
    const events = [...this._domainEvents];
    this._domainEvents.length = 0;
    return events;
  }

  // ── Queries ────────────────────────────────────────────────────────────────

  getId(): UserId {
    return this._id;
  }

  getTenantId(): TenantId {
    return this._tenantId;
  }

  getStatus(): UserStatus {
    return this._status;
  }

  getVersion(): number {
    return this._version;
  }

  getCredential(): Credential | undefined {
    return this._credential;
  }

  getIdentity(type: IdentityType): Identity | undefined {
    return this._identities.find((i) => i.getType() === type);
  }

  getIdentities(): Identity[] {
    return [...this._identities];
  }

  getVerifiedIdentities(): Identity[] {
    return this._identities.filter((i) => i.isVerified());
  }

  isActive(): boolean {
    return this._status === 'ACTIVE';
  }

  isSuspended(): boolean {
    return this._status === 'SUSPENDED';
  }

  /** Returns true if the user is suspended AND the suspension period has not yet elapsed. */
  isSuspendedNow(): boolean {
    if (this._status !== 'SUSPENDED') return false;
    if (!this._suspendUntil) return true; // indefinite suspension
    return this._suspendUntil > new Date();
  }

  getSuspendUntil(): Date | undefined {
    return this._suspendUntil;
  }

  getCreatedAt(): Date {
    return this._createdAt;
  }

  getUpdatedAt(): Date {
    return this._updatedAt;
  }

  // ── Private Helpers ────────────────────────────────────────────────────────

  private _nextSeq(): number {
    return this._version + this._domainEvents.length + 1;
  }
}

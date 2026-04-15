import { DomainEvent } from './domain-event.base';
import { IdentityType } from '../entities/identity.entity';

// ── User lifecycle events ──────────────────────────────────────────────────

export class UserCreatedEvent extends DomainEvent {
  readonly eventType = 'UserCreated' as const;
  constructor(
    public readonly payload: { userId: string; tenantId: string; createdAt: string },
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.userId, aggregateType: 'User', aggregateSeq, tenantId: payload.tenantId });
  }
}

export class UserActivatedEvent extends DomainEvent {
  readonly eventType = 'UserActivated' as const;
  constructor(
    public readonly payload: { userId: string; activatedAt: string },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.userId, aggregateType: 'User', aggregateSeq, tenantId });
  }
}

export class UserSuspendedEvent extends DomainEvent {
  readonly eventType = 'UserSuspended' as const;
  constructor(
    public readonly payload: { userId: string; reason: string; until?: string },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.userId, aggregateType: 'User', aggregateSeq, tenantId });
  }
}

export class UserUnsuspendedEvent extends DomainEvent {
  readonly eventType = 'UserUnsuspended' as const;
  constructor(
    public readonly payload: { userId: string },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.userId, aggregateType: 'User', aggregateSeq, tenantId });
  }
}

export class UserDeletedEvent extends DomainEvent {
  readonly eventType = 'UserDeleted' as const;
  constructor(
    public readonly payload: { userId: string; deletedAt: string },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.userId, aggregateType: 'User', aggregateSeq, tenantId });
  }
}

export class IdentityLinkedEvent extends DomainEvent {
  readonly eventType = 'IdentityLinked' as const;
  constructor(
    public readonly payload: { identityId: string; type: IdentityType; userId: string },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.userId, aggregateType: 'User', aggregateSeq, tenantId });
  }
}

export class IdentityVerifiedEvent extends DomainEvent {
  readonly eventType = 'IdentityVerified' as const;
  constructor(
    public readonly payload: { identityId: string; type: IdentityType; verifiedAt: string },
    userId: string,
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: userId, aggregateType: 'User', aggregateSeq, tenantId });
  }
}

export class PasswordChangedEvent extends DomainEvent {
  readonly eventType = 'PasswordChanged' as const;
  constructor(
    public readonly payload: { userId: string; algorithm: string; changedAt: string },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.userId, aggregateType: 'User', aggregateSeq, tenantId });
  }
}

export type UserDomainEvent =
  | UserCreatedEvent
  | UserActivatedEvent
  | UserSuspendedEvent
  | UserUnsuspendedEvent
  | UserDeletedEvent
  | IdentityLinkedEvent
  | IdentityVerifiedEvent
  | PasswordChangedEvent;

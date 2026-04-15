import { DomainEvent } from './domain-event.base';

export class SessionCreatedEvent extends DomainEvent {
  readonly eventType = 'SessionCreated' as const;
  constructor(
    public readonly payload: {
      sessionId: string;
      userId: string;
      ipHash: string;
      uaBrowser: string;
    },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.sessionId, aggregateType: 'Session', aggregateSeq, tenantId });
  }
}

export class SessionRevokedEvent extends DomainEvent {
  readonly eventType = 'SessionRevoked' as const;
  constructor(
    public readonly payload: { sessionId: string; reason: string; revokedAt: string },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.sessionId, aggregateType: 'Session', aggregateSeq, tenantId });
  }
}

export type SessionDomainEvent = SessionCreatedEvent | SessionRevokedEvent;

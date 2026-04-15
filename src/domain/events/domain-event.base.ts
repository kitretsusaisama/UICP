import { randomUUID } from 'crypto';

/**
 * Base class for all domain events.
 * Every event carries identity, ordering, and tenant context.
 */
export abstract class DomainEvent {
  readonly eventId: string;
  readonly aggregateId: string;
  readonly aggregateType: string;
  /** Discriminator — set by each concrete subclass as a `const` literal. */
  abstract readonly eventType: string;
  /** Monotonically increasing sequence number per aggregate — used for optimistic concurrency. */
  readonly aggregateSeq: number;
  readonly occurredAt: Date;
  readonly tenantId: string;

  protected constructor(params: {
    aggregateId: string;
    aggregateType: string;
    aggregateSeq: number;
    tenantId: string;
    occurredAt?: Date;
  }) {
    this.eventId = randomUUID();
    this.aggregateId = params.aggregateId;
    this.aggregateType = params.aggregateType;
    this.aggregateSeq = params.aggregateSeq;
    this.tenantId = params.tenantId;
    this.occurredAt = params.occurredAt ?? new Date();
  }
}

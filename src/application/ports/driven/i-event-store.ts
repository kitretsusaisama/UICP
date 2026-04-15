import { DomainEvent } from '../../../domain/events/domain-event.base';

/**
 * Driven port — append-only event store for event sourcing.
 *
 * Contract:
 * - `append` uses INSERT with a UNIQUE KEY on (aggregate_id, aggregate_seq)
 *   to enforce optimistic concurrency — throws on duplicate seq (Req 6.6).
 * - `loadEvents` returns events ordered by `aggregate_seq ASC`.
 * - Events are immutable once written.
 */
export interface IEventStore {
  /**
   * Append new domain events for an aggregate.
   * Throws `ConflictException(VERSION_CONFLICT)` if any event's `aggregateSeq`
   * already exists for the given `aggregateId` (duplicate seq = concurrent write).
   */
  append(aggregateId: string, events: DomainEvent[]): Promise<void>;

  /**
   * Load all events for an aggregate, ordered by `aggregateSeq ASC`.
   * Returns an empty array when the aggregate has no events.
   */
  loadEvents(aggregateId: string): Promise<DomainEvent[]>;
}

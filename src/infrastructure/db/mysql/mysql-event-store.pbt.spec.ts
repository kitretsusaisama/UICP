/**
 * Property-Based Test — Event Store Append Ordering (Property 4)
 *
 * **Property 4: Concurrent appends with same aggregate_seq — exactly one
 * succeeds, rest throw VERSION_CONFLICT**
 *
 * **Validates: Req 7 (event sourcing), Req 6.6**
 *
 * Strategy: Use an in-memory stub of IEventStore that faithfully replicates
 * the optimistic-concurrency semantics of MysqlEventStoreRepository:
 *   - INSERT with UNIQUE KEY on (aggregateId, aggregateSeq)
 *   - Duplicate seq → ConflictException(VERSION_CONFLICT)
 *   - loadEvents() always returns events ordered by aggregateSeq ASC
 *
 * This is a pure unit / property test — no real database required.
 */

import * as fc from 'fast-check';
import { ConflictException } from '@nestjs/common';
import { IEventStore } from '../../../application/ports/driven/i-event-store';
import { DomainEvent } from '../../../domain/events/domain-event.base';

// ── In-memory stub with optimistic concurrency ─────────────────────────────

/**
 * Minimal in-memory IEventStore that replicates the MySQL adapter's
 * optimistic-concurrency guarantee:
 *
 *   INSERT INTO domain_events ... (uq_aggregate_seq unique key)
 *   → ER_DUP_ENTRY → ConflictException('VERSION_CONFLICT')
 *
 * A per-aggregate write mutex serialises concurrent appends so the
 * uniqueness check is atomic — exactly as InnoDB serialises concurrent
 * INSERTs under the unique key constraint.
 */
class InMemoryEventStore implements IEventStore {
  /** Map of `${aggregateId}:${aggregateSeq}` → DomainEvent */
  private readonly store = new Map<string, DomainEvent>();

  /** Per-aggregate write mutex (Promise chain). */
  private readonly writeLocks = new Map<string, Promise<void>>();

  async append(aggregateId: string, events: DomainEvent[]): Promise<void> {
    if (events.length === 0) return;

    const previous = this.writeLocks.get(aggregateId) ?? Promise.resolve();
    let resolveTail!: () => void;
    const tail = new Promise<void>((res) => { resolveTail = res; });
    this.writeLocks.set(aggregateId, tail);

    try {
      await previous;

      for (const event of events) {
        const key = `${aggregateId}:${event.aggregateSeq}`;
        if (this.store.has(key)) {
          throw new ConflictException('VERSION_CONFLICT');
        }
        this.store.set(key, event);
      }
    } finally {
      resolveTail();
    }
  }

  async loadEvents(aggregateId: string): Promise<DomainEvent[]> {
    const events: DomainEvent[] = [];
    for (const [key, event] of this.store) {
      if (key.startsWith(`${aggregateId}:`)) {
        events.push(event);
      }
    }
    // Always return in ascending aggregateSeq order
    return events.sort((a, b) => a.aggregateSeq - b.aggregateSeq);
  }
}

// ── Fixtures ───────────────────────────────────────────────────────────────

function makeEvent(aggregateId: string, aggregateSeq: number, tenantId = 'tenant-001'): DomainEvent {
  return {
    eventId: crypto.randomUUID(),
    aggregateId,
    aggregateType: 'User',
    eventType: 'UserCreated',
    aggregateSeq,
    tenantId,
    occurredAt: new Date(),
    payload: { seq: aggregateSeq },
  } as unknown as DomainEvent;
}

// ── Property 4 ─────────────────────────────────────────────────────────────

describe('Property 4 — Event store append ordering (Req 7, Req 6.6)', () => {
  /**
   * Core property: two concurrent appends with the same aggregateSeq —
   * exactly one succeeds, the other throws VERSION_CONFLICT.
   */
  it('concurrent appends with same aggregateSeq: exactly 1 succeeds, 1 throws VERSION_CONFLICT', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.integer({ min: 1, max: 100 }),
        async (aggregateId, seq) => {
          const store = new InMemoryEventStore();

          const eventA = makeEvent(aggregateId, seq);
          const eventB = makeEvent(aggregateId, seq); // same seq — conflict

          const results = await Promise.allSettled([
            store.append(aggregateId, [eventA]),
            store.append(aggregateId, [eventB]),
          ]);

          const fulfilled = results.filter((r) => r.status === 'fulfilled');
          const rejected = results.filter((r) => r.status === 'rejected');

          expect(fulfilled).toHaveLength(1);
          expect(rejected).toHaveLength(1);

          const reason = (rejected[0] as PromiseRejectedResult).reason;
          expect(reason).toBeInstanceOf(ConflictException);
          expect((reason as ConflictException).message).toBe('VERSION_CONFLICT');
        },
      ),
      { numRuns: 200 },
    );
  });

  it('N concurrent appends with same aggregateSeq: exactly 1 succeeds, N-1 throw VERSION_CONFLICT', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.integer({ min: 2, max: 8 }),
        async (aggregateId, concurrency) => {
          const store = new InMemoryEventStore();
          const seq = 1;

          const results = await Promise.allSettled(
            Array.from({ length: concurrency }, (_, i) =>
              store.append(aggregateId, [makeEvent(aggregateId, seq, `tenant-${i}`)]),
            ),
          );

          const fulfilled = results.filter((r) => r.status === 'fulfilled');
          const rejected = results.filter((r) => r.status === 'rejected');

          expect(fulfilled).toHaveLength(1);
          expect(rejected).toHaveLength(concurrency - 1);

          for (const r of rejected) {
            const reason = (r as PromiseRejectedResult).reason;
            expect(reason).toBeInstanceOf(ConflictException);
            expect((reason as ConflictException).message).toBe('VERSION_CONFLICT');
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  /**
   * loadEvents() always returns events in ascending aggregateSeq order,
   * regardless of insertion order.
   */
  it('loadEvents() always returns events in ascending aggregateSeq order', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.array(fc.integer({ min: 1, max: 1000 }), { minLength: 1, maxLength: 20 }),
        async (aggregateId, seqs) => {
          // Deduplicate seqs to avoid VERSION_CONFLICT during setup
          const uniqueSeqs = [...new Set(seqs)];
          const store = new InMemoryEventStore();

          // Append events in arbitrary (shuffled) order
          const shuffled = [...uniqueSeqs].sort(() => Math.random() - 0.5);
          for (const seq of shuffled) {
            await store.append(aggregateId, [makeEvent(aggregateId, seq)]);
          }

          const loaded = await store.loadEvents(aggregateId);

          // Must be sorted ascending
          for (let i = 1; i < loaded.length; i++) {
            expect(loaded[i]!.aggregateSeq).toBeGreaterThan(loaded[i - 1]!.aggregateSeq);
          }

          // Must contain all appended events
          expect(loaded).toHaveLength(uniqueSeqs.length);
        },
      ),
      { numRuns: 200 },
    );
  });

  it('sequential appends with distinct seqs always succeed', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.integer({ min: 1, max: 20 }),
        async (aggregateId, eventCount) => {
          const store = new InMemoryEventStore();

          for (let seq = 1; seq <= eventCount; seq++) {
            await expect(
              store.append(aggregateId, [makeEvent(aggregateId, seq)]),
            ).resolves.toBeUndefined();
          }

          const loaded = await store.loadEvents(aggregateId);
          expect(loaded).toHaveLength(eventCount);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('appending to different aggregates never conflicts', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 2, max: 10 }),
        async (aggregateCount) => {
          const store = new InMemoryEventStore();
          const aggregateIds = Array.from({ length: aggregateCount }, () => crypto.randomUUID());

          // All aggregates append seq=1 concurrently — no conflicts expected
          const results = await Promise.allSettled(
            aggregateIds.map((id) => store.append(id, [makeEvent(id, 1)])),
          );

          const fulfilled = results.filter((r) => r.status === 'fulfilled');
          expect(fulfilled).toHaveLength(aggregateCount);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('loadEvents() returns empty array for unknown aggregateId', async () => {
    const store = new InMemoryEventStore();
    const events = await store.loadEvents(crypto.randomUUID());
    expect(events).toEqual([]);
  });
});

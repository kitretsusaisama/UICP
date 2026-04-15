/**
 * Property-Based Test — Outbox At-Least-Once Delivery (Property 19)
 *
 * **Property 19: Every outbox event eventually reaches status PUBLISHED or DLQ
 * — never stays PENDING indefinitely**
 *
 * **Validates: Req 4.5**
 *
 * Strategy: Use an in-memory stub of IOutboxRepository and a mock BullMQ
 * adapter. For N arbitrary outbox events, run the relay worker's pollAndRelay()
 * loop until all events reach a terminal status (PUBLISHED or DLQ).
 * Assert that no event remains in PENDING or FAILED status after the loop.
 *
 * The relay worker retries up to MAX_ATTEMPTS (5) times before moving to DLQ,
 * so the property holds regardless of transient publish failures.
 */

import * as fc from 'fast-check';
import { OutboxRelayWorker } from './outbox-relay.worker';
import { IOutboxRepository, OutboxEvent } from '../../../application/ports/driven/i-outbox.repository';
import { BullMqQueueAdapter, QUEUE_NAMES } from '../bullmq-queue.adapter';

// ── In-memory outbox repository ────────────────────────────────────────────

const MAX_ATTEMPTS = 5;

class InMemoryOutboxRepository implements IOutboxRepository {
  private readonly store = new Map<string, OutboxEvent>();

  seed(events: OutboxEvent[]): void {
    for (const e of events) {
      this.store.set(e.id, { ...e });
    }
  }

  async insertWithinTransaction(event: OutboxEvent): Promise<void> {
    this.store.set(event.id, { ...event });
  }

  async claimPendingBatch(limit: number): Promise<OutboxEvent[]> {
    const pending: OutboxEvent[] = [];
    for (const event of this.store.values()) {
      if (event.status === 'PENDING' || event.status === 'FAILED') {
        pending.push({ ...event });
        if (pending.length >= limit) break;
      }
    }
    return pending;
  }

  async markPublished(eventId: string): Promise<void> {
    const event = this.store.get(eventId);
    if (event) {
      this.store.set(eventId, { ...event, status: 'PUBLISHED', publishedAt: new Date() });
    }
  }

  async markFailed(eventId: string, error: string): Promise<void> {
    const event = this.store.get(eventId);
    if (event) {
      this.store.set(eventId, { ...event, status: 'FAILED', attempts: event.attempts + 1, lastError: error });
    }
  }

  async moveToDlq(eventId: string): Promise<void> {
    const event = this.store.get(eventId);
    if (event) {
      this.store.set(eventId, { ...event, status: 'DLQ' });
    }
  }

  getAll(): OutboxEvent[] {
    return [...this.store.values()];
  }

  getPending(): OutboxEvent[] {
    return this.getAll().filter((e) => e.status === 'PENDING' || e.status === 'FAILED');
  }

  getTerminal(): OutboxEvent[] {
    return this.getAll().filter((e) => e.status === 'PUBLISHED' || e.status === 'DLQ');
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

function makeOutboxEvent(overrides: Partial<OutboxEvent> = {}): OutboxEvent {
  return {
    id: crypto.randomUUID(),
    eventType: 'UserCreated',
    aggregateId: crypto.randomUUID(),
    aggregateType: 'User',
    tenantId: 'tenant-001',
    payload: {},
    status: 'PENDING',
    attempts: 0,
    createdAt: new Date(),
    ...overrides,
  };
}

function buildWorker(
  outboxRepo: IOutboxRepository,
  enqueue: jest.Mock,
): OutboxRelayWorker {
  const queueAdapter = { enqueue } as unknown as BullMqQueueAdapter;
  const config = { get: jest.fn().mockReturnValue(undefined) } as any;
  return new OutboxRelayWorker(outboxRepo, queueAdapter, config);
}

/**
 * Run pollAndRelay() in a loop until no more PENDING/FAILED events remain,
 * or until maxIterations is reached (safety guard against infinite loops).
 */
async function drainOutbox(
  worker: OutboxRelayWorker,
  repo: InMemoryOutboxRepository,
  maxIterations = 100,
): Promise<void> {
  for (let i = 0; i < maxIterations; i++) {
    if (repo.getPending().length === 0) break;
    await (worker as any).pollAndRelay();
  }
}

// ── Property 19 ────────────────────────────────────────────────────────────

describe('Property 19 — Outbox at-least-once delivery (Req 4.5)', () => {
  /**
   * Core property: when publish always succeeds, all events reach PUBLISHED.
   */
  it('all events reach PUBLISHED when publish never fails', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 20 }),
        async (eventCount) => {
          const repo = new InMemoryOutboxRepository();
          const events = Array.from({ length: eventCount }, () => makeOutboxEvent());
          repo.seed(events);

          const enqueue = jest.fn().mockResolvedValue(undefined);
          const worker = buildWorker(repo, enqueue);

          await drainOutbox(worker, repo);

          const all = repo.getAll();
          expect(all).toHaveLength(eventCount);
          for (const event of all) {
            expect(event.status).toBe('PUBLISHED');
          }
          expect(repo.getPending()).toHaveLength(0);
        },
      ),
      { numRuns: 100 },
    );
  });

  /**
   * Core property: when publish always fails, all events eventually reach DLQ
   * after MAX_ATTEMPTS retries — none stay PENDING indefinitely.
   */
  it('all events reach DLQ when publish always fails (after MAX_ATTEMPTS retries)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 10 }),
        async (eventCount) => {
          const repo = new InMemoryOutboxRepository();
          const events = Array.from({ length: eventCount }, () => makeOutboxEvent());
          repo.seed(events);

          const enqueue = jest.fn().mockRejectedValue(new Error('publish failed'));
          const worker = buildWorker(repo, enqueue);

          // Run enough iterations to exhaust all retries
          // Each event needs MAX_ATTEMPTS (5) poll cycles to reach DLQ
          await drainOutbox(worker, repo, eventCount * (MAX_ATTEMPTS + 2));

          const all = repo.getAll();
          expect(all).toHaveLength(eventCount);
          for (const event of all) {
            expect(['PUBLISHED', 'DLQ']).toContain(event.status);
          }
          expect(repo.getPending()).toHaveLength(0);
        },
      ),
      { numRuns: 50 },
    );
  });

  /**
   * Mixed scenario: some events succeed, some fail transiently then succeed,
   * some fail permanently and reach DLQ. All must reach a terminal status.
   */
  it('all events reach terminal status (PUBLISHED or DLQ) regardless of publish reliability', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 15 }),
        // Failure probability: 0 = always succeed, 1 = always fail
        fc.float({ min: 0, max: 1, noNaN: true }),
        async (eventCount, failureProbability) => {
          const repo = new InMemoryOutboxRepository();
          const events = Array.from({ length: eventCount }, () => makeOutboxEvent());
          repo.seed(events);

          const enqueue = jest.fn().mockImplementation(() => {
            if (Math.random() < failureProbability) {
              return Promise.reject(new Error('transient failure'));
            }
            return Promise.resolve();
          });
          const worker = buildWorker(repo, enqueue);

          // Run enough iterations to exhaust all retries for all events
          await drainOutbox(worker, repo, eventCount * (MAX_ATTEMPTS + 5));

          // No event should remain in a non-terminal state
          const pending = repo.getPending();
          expect(pending).toHaveLength(0);

          // All events must be in a terminal state
          for (const event of repo.getAll()) {
            expect(['PUBLISHED', 'DLQ']).toContain(event.status);
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  /**
   * Events that start with attempts > 0 (partially retried) still reach
   * terminal status within the remaining retry budget.
   */
  it('events with pre-existing attempts still reach terminal status', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: MAX_ATTEMPTS - 1 }),
        async (existingAttempts) => {
          const repo = new InMemoryOutboxRepository();
          // Event already has some failed attempts
          const event = makeOutboxEvent({ attempts: existingAttempts, status: 'FAILED' });
          repo.seed([event]);

          // Always fail — event should reach DLQ after remaining retries
          const enqueue = jest.fn().mockRejectedValue(new Error('always fails'));
          const worker = buildWorker(repo, enqueue);

          await drainOutbox(worker, repo, MAX_ATTEMPTS + 2);

          const final = repo.getAll()[0]!;
          expect(['PUBLISHED', 'DLQ']).toContain(final.status);
          expect(repo.getPending()).toHaveLength(0);
        },
      ),
      { numRuns: 50 },
    );
  });

  /**
   * Empty outbox: draining an empty outbox is a no-op and does not throw.
   */
  it('draining an empty outbox is a no-op', async () => {
    const repo = new InMemoryOutboxRepository();
    const enqueue = jest.fn();
    const worker = buildWorker(repo, enqueue);

    await expect(drainOutbox(worker, repo, 5)).resolves.toBeUndefined();
    expect(enqueue).not.toHaveBeenCalled();
    expect(repo.getPending()).toHaveLength(0);
  });
});

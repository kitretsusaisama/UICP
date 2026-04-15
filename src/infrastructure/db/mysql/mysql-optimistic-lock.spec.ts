/**
 * Property 3: Concurrent updates with same version — exactly one succeeds,
 * rest throw VERSION_CONFLICT
 *
 * Validates: Req 2.7
 *
 * Strategy: Use an in-memory stub of IUserRepository that faithfully
 * replicates the optimistic-locking semantics of the MySQL adapter
 * (version check + increment, ConflictException on mismatch). Run two
 * concurrent `update()` calls against the same user at the same version
 * and assert that exactly one fulfills and exactly one rejects with
 * VERSION_CONFLICT.
 *
 * This is a pure unit / property test — no real database required.
 */

import * as fc from 'fast-check';
import { ConflictException } from '@nestjs/common';
import { IUserRepository } from '../../../application/ports/driven/i-user.repository';
import { User } from '../../../domain/aggregates/user.aggregate';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { toEncryptedValue } from '../../../domain/entities/identity.entity';

// ── In-memory stub with optimistic locking ─────────────────────────────────

/**
 * Minimal in-memory IUserRepository that replicates the optimistic-locking
 * semantics of MysqlUserRepository:
 *
 *   UPDATE users SET version = version + 1 WHERE id = ? AND version = ?
 *   → affectedRows === 0  →  throw ConflictException('VERSION_CONFLICT')
 *
 * A Mutex (Promise chain) serialises concurrent writes to the same key so
 * that the check-then-increment is atomic — exactly as InnoDB row-level
 * locking serialises concurrent UPDATE statements.
 */
class InMemoryUserRepositoryWithOptimisticLock implements IUserRepository {
  /** Stored snapshot: version is the source of truth. */
  private readonly store = new Map<string, { user: User; version: number }>();

  /**
   * Per-key write mutex: each key holds the tail of a Promise chain.
   * Concurrent writes are serialised through this chain so the
   * check-then-increment is atomic (mirrors InnoDB row-level locking).
   */
  private readonly writeLocks = new Map<string, Promise<void>>();

  async findById(userId: UserId, tenantId: TenantId): Promise<User | null> {
    const key = this._key(userId, tenantId);
    const entry = this.store.get(key);
    if (!entry) return null;
    // Return a snapshot reconstituted with the current stored version so
    // callers always see the up-to-date version number after an update.
    return User.reconstitute({
      id: entry.user.getId(),
      tenantId: entry.user.getTenantId(),
      status: entry.user.getStatus(),
      identities: entry.user.getIdentities(),
      credential: entry.user.getCredential(),
      suspendUntil: entry.user.getSuspendUntil(),
      version: entry.version,
      createdAt: entry.user.getCreatedAt(),
      updatedAt: entry.user.getUpdatedAt(),
    });
  }

  async findByTenantId(tenantId: TenantId): Promise<User[]> {
    const results: User[] = [];
    for (const [key, entry] of this.store) {
      if (key.startsWith(`${tenantId.toString()}:`)) {
        results.push(entry.user);
      }
    }
    return results;
  }

  async save(user: User): Promise<void> {
    const key = this._key(user.getId(), user.getTenantId());
    this.store.set(key, { user, version: user.getVersion() });
  }

  /**
   * Serialised optimistic-lock update.
   *
   * Enqueues behind any in-flight write for the same key so that the
   * version check + increment is atomic — exactly as a MySQL UPDATE with
   * WHERE version = ? serialises under InnoDB row locking.
   */
  async update(user: User): Promise<void> {
    const key = this._key(user.getId(), user.getTenantId());

    // Chain this write behind the current tail for this key
    const previous = this.writeLocks.get(key) ?? Promise.resolve();
    let resolveTail!: () => void;
    const tail = new Promise<void>((res) => { resolveTail = res; });
    this.writeLocks.set(key, tail);

    try {
      // Wait for any concurrent write that started before us to finish
      await previous;

      const stored = this.store.get(key);
      if (!stored || stored.version !== user.getVersion()) {
        throw new ConflictException('VERSION_CONFLICT');
      }

      // Atomically increment version and persist
      const newVersion = stored.version + 1;
      this.store.set(key, { user, version: newVersion });
    } finally {
      resolveTail();
    }
  }

  private _key(userId: UserId, tenantId: TenantId): string {
    return `${tenantId.toString()}:${userId.toString()}`;
  }
}

// ── Fixtures ───────────────────────────────────────────────────────────────

function buildActiveUser(tenantId: TenantId): User {
  const user = User.createWithEmail({
    email: {
      getValue: () => 'user@example.com',
      getDomain: () => 'example.com',
      toHmacInput: () => 'user@example.com',
      toString: () => 'user@example.com',
    } as any,
    tenantId,
    emailEnc: toEncryptedValue('iv.tag.cipher.kid1'),
    emailHash: `hash-${Math.random()}`,
  });

  // Verify the identity to transition PENDING → ACTIVE
  const identity = user.getIdentities()[0]!;
  user.verifyIdentity(identity.id);

  return user;
}

// ── Property 3 ─────────────────────────────────────────────────────────────

/**
 * Property 3: Concurrent updates with same version — exactly one succeeds,
 * rest throw VERSION_CONFLICT
 *
 * Validates: Req 2.7
 */
describe('Property 3 — Optimistic lock concurrency: exactly one concurrent update succeeds', () => {
  /**
   * Core property: for any number of concurrent callers (2–5) all holding
   * the same version snapshot, exactly one update must succeed and all
   * others must be rejected with VERSION_CONFLICT.
   */
  it('exactly 1 of N concurrent updates succeeds; the rest throw VERSION_CONFLICT', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Number of concurrent callers: 2 to 5
        fc.integer({ min: 2, max: 5 }),
        async (concurrency) => {
          const repo = new InMemoryUserRepositoryWithOptimisticLock();
          const tenantId = TenantId.create();

          // Persist the initial user (version = 0)
          const user = buildActiveUser(tenantId);
          await repo.save(user);

          // All callers read the same snapshot (version = 0) before any write
          const snapshot = await repo.findById(user.getId(), tenantId);
          expect(snapshot).not.toBeNull();

          // Each caller suspends the user (a valid mutation) using the same version
          const updates = Array.from({ length: concurrency }, () => {
            // Reconstitute a fresh copy at the same version so each caller
            // independently believes it holds the current version
            const copy = User.reconstitute({
              id: snapshot!.getId(),
              tenantId: snapshot!.getTenantId(),
              status: snapshot!.getStatus(),
              identities: snapshot!.getIdentities(),
              credential: snapshot!.getCredential(),
              suspendUntil: snapshot!.getSuspendUntil(),
              version: snapshot!.getVersion(),
              createdAt: snapshot!.getCreatedAt(),
              updatedAt: snapshot!.getUpdatedAt(),
            });
            copy.suspend('concurrent-update-test');
            return repo.update(copy);
          });

          const results = await Promise.allSettled(updates);

          const fulfilled = results.filter((r) => r.status === 'fulfilled');
          const rejected = results.filter((r) => r.status === 'rejected');

          // Exactly one update must succeed
          expect(fulfilled).toHaveLength(1);

          // All others must fail with VERSION_CONFLICT
          expect(rejected).toHaveLength(concurrency - 1);
          for (const r of rejected) {
            expect(r.status).toBe('rejected');
            const reason = (r as PromiseRejectedResult).reason;
            expect(reason).toBeInstanceOf(ConflictException);
            expect((reason as ConflictException).message).toBe('VERSION_CONFLICT');
          }
        },
      ),
      { numRuns: 50 },
    );
  });

  /**
   * Focused 2-caller variant matching the task spec exactly:
   * "Use fc.asyncProperty with Promise.allSettled on 2 concurrent updates;
   *  assert exactly 1 fulfilled, 1 rejected with VERSION_CONFLICT"
   */
  it('2 concurrent updates: exactly 1 fulfilled, 1 rejected with VERSION_CONFLICT', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Arbitrary tenant to vary the test universe
        fc.uuid(),
        async (_tenantSeed) => {
          const repo = new InMemoryUserRepositoryWithOptimisticLock();
          const tenantId = TenantId.create();

          const user = buildActiveUser(tenantId);
          await repo.save(user);

          const snapshot = await repo.findById(user.getId(), tenantId);
          expect(snapshot).not.toBeNull();

          // Two callers, both holding version = snapshot.getVersion()
          const makeUpdate = () => {
            const copy = User.reconstitute({
              id: snapshot!.getId(),
              tenantId: snapshot!.getTenantId(),
              status: snapshot!.getStatus(),
              identities: snapshot!.getIdentities(),
              credential: snapshot!.getCredential(),
              suspendUntil: snapshot!.getSuspendUntil(),
              version: snapshot!.getVersion(),
              createdAt: snapshot!.getCreatedAt(),
              updatedAt: snapshot!.getUpdatedAt(),
            });
            copy.suspend('concurrent-update-test');
            return repo.update(copy);
          };

          const [resultA, resultB] = await Promise.allSettled([makeUpdate(), makeUpdate()]);

          const fulfilled = [resultA, resultB].filter((r) => r.status === 'fulfilled');
          const rejected = [resultA, resultB].filter((r) => r.status === 'rejected');

          // Exactly 1 fulfilled, 1 rejected
          expect(fulfilled).toHaveLength(1);
          expect(rejected).toHaveLength(1);

          const reason = (rejected[0] as PromiseRejectedResult).reason;
          expect(reason).toBeInstanceOf(ConflictException);
          expect((reason as ConflictException).message).toBe('VERSION_CONFLICT');
        },
      ),
      { numRuns: 100 },
    );
  });

  /**
   * Sequential updates succeed: after a successful update the version
   * increments, so the next caller with the new version also succeeds.
   */
  it('sequential updates with correct version always succeed', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 10 }),
        async (updateCount) => {
          const repo = new InMemoryUserRepositoryWithOptimisticLock();
          const tenantId = TenantId.create();

          const user = buildActiveUser(tenantId);
          await repo.save(user);

          // Each sequential update reads the latest version before writing
          for (let i = 0; i < updateCount; i++) {
            const current = await repo.findById(user.getId(), tenantId);
            expect(current).not.toBeNull();

            const copy = User.reconstitute({
              id: current!.getId(),
              tenantId: current!.getTenantId(),
              status: current!.getStatus(),
              identities: current!.getIdentities(),
              credential: current!.getCredential(),
              suspendUntil: current!.getSuspendUntil(),
              version: current!.getVersion(),
              createdAt: current!.getCreatedAt(),
              updatedAt: current!.getUpdatedAt(),
            });

            // Alternate between suspend and unsuspend to keep transitions valid
            if (copy.getStatus() === 'ACTIVE') {
              copy.suspend('sequential-test');
            } else if (copy.getStatus() === 'SUSPENDED') {
              copy.unsuspend();
            }

            await expect(repo.update(copy)).resolves.toBeUndefined();
          }
        },
      ),
    );
  });

  /**
   * Stale version always rejected: a caller holding an outdated version
   * must always receive VERSION_CONFLICT, even when no concurrent caller
   * is present.
   */
  it('stale version is always rejected with VERSION_CONFLICT', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 5 }),
        async (staleness) => {
          const repo = new InMemoryUserRepositoryWithOptimisticLock();
          const tenantId = TenantId.create();

          const user = buildActiveUser(tenantId);
          await repo.save(user);

          // Capture a stale snapshot before advancing the version
          const staleSnapshot = await repo.findById(user.getId(), tenantId);
          expect(staleSnapshot).not.toBeNull();

          // Advance the version `staleness` times via sequential updates,
          // alternating suspend/unsuspend to keep transitions valid.
          for (let i = 0; i < staleness; i++) {
            const current = await repo.findById(user.getId(), tenantId);
            const copy = User.reconstitute({
              id: current!.getId(),
              tenantId: current!.getTenantId(),
              status: current!.getStatus(),
              identities: current!.getIdentities(),
              credential: current!.getCredential(),
              suspendUntil: current!.getSuspendUntil(),
              version: current!.getVersion(),
              createdAt: current!.getCreatedAt(),
              updatedAt: current!.getUpdatedAt(),
            });
            if (copy.getStatus() === 'ACTIVE') copy.suspend('advance');
            else if (copy.getStatus() === 'SUSPENDED') copy.unsuspend();
            await repo.update(copy);
          }

          // Now attempt an update with the stale snapshot.
          // Apply a mutation that is valid for the stale snapshot's status.
          const stale = User.reconstitute({
            id: staleSnapshot!.getId(),
            tenantId: staleSnapshot!.getTenantId(),
            status: staleSnapshot!.getStatus(),
            identities: staleSnapshot!.getIdentities(),
            credential: staleSnapshot!.getCredential(),
            suspendUntil: staleSnapshot!.getSuspendUntil(),
            version: staleSnapshot!.getVersion(), // outdated version
            createdAt: staleSnapshot!.getCreatedAt(),
            updatedAt: staleSnapshot!.getUpdatedAt(),
          });
          // Apply a valid mutation for the stale status
          if (stale.getStatus() === 'ACTIVE') stale.suspend('stale-update');
          else if (stale.getStatus() === 'SUSPENDED') stale.unsuspend();

          await expect(repo.update(stale)).rejects.toThrow(
            expect.objectContaining({ message: 'VERSION_CONFLICT' }),
          );
        },
      ),
    );
  });
});

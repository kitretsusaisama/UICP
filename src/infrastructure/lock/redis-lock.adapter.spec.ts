import * as fc from 'fast-check';
import { RedisLockAdapter } from './redis-lock.adapter';
import { LockToken } from '../../application/ports/driven/i-lock.port';

// ── In-Memory Redis Mock ───────────────────────────────────────────────────

/**
 * Minimal in-memory Redis mock that faithfully implements the SET NX PX and
 * Lua eval semantics used by RedisLockAdapter.
 *
 * All operations are synchronous under the hood, but exposed as async to match
 * the ioredis API. This makes concurrent Promise.allSettled tests deterministic
 * without requiring a real Redis instance.
 */
class InMemoryRedisClient {
  private readonly store = new Map<string, { value: string; expiresAt: number }>();

  /** SET key value NX PX ttl — returns 'OK' if set, null if key already exists. */
  async set(
    key: string,
    value: string,
    _px: 'PX',
    ttlMs: number,
    _nx: 'NX',
  ): Promise<'OK' | null> {
    this.evictExpired(key);
    if (this.store.has(key)) return null;
    this.store.set(key, { value, expiresAt: Date.now() + ttlMs });
    return 'OK';
  }

  /** GET key — returns the value or null if missing/expired. */
  async get(key: string): Promise<string | null> {
    this.evictExpired(key);
    return this.store.get(key)?.value ?? null;
  }

  /** DEL key — returns 1 if deleted, 0 if not found. */
  async del(key: string): Promise<number> {
    return this.store.delete(key) ? 1 : 0;
  }

  /**
   * eval(script, numKeys, key, argv...) — executes the Lua release/extend scripts.
   *
   * RELEASE_SCRIPT: if GET(key) == argv[0] then DEL(key) → 1 else 0
   * EXTEND_SCRIPT:  if GET(key) == argv[0] then PEXPIRE(key, argv[1]) → 1 else 0
   */
  async eval(script: string, _numKeys: number, key: string, ...args: string[]): Promise<number> {
    this.evictExpired(key);
    const entry = this.store.get(key);

    if (!entry || entry.value !== args[0]) return 0;

    if (script.includes('DEL')) {
      this.store.delete(key);
      return 1;
    }

    if (script.includes('PEXPIRE')) {
      const additionalMs = parseInt(args[1]!, 10);
      entry.expiresAt = Date.now() + additionalMs;
      return 1;
    }

    return 0;
  }

  /** Force-delete a key (test helper). */
  forceDelete(key: string): void {
    this.store.delete(key);
  }

  /** Check if a key exists (test helper). */
  has(key: string): boolean {
    this.evictExpired(key);
    return this.store.has(key);
  }

  private evictExpired(key: string): void {
    const entry = this.store.get(key);
    if (entry && Date.now() >= entry.expiresAt) {
      this.store.delete(key);
    }
  }
}

// ── Test Factory ───────────────────────────────────────────────────────────

function buildAdapter(client: InMemoryRedisClient): RedisLockAdapter {
  const mockCache = {
    getClient: () => client,
    isCircuitOpen: () => false,
  } as any;
  return new RedisLockAdapter(mockCache);
}

// ── Property Tests ─────────────────────────────────────────────────────────

/**
 * Property 15: At most one process holds a given lock key at any point in time
 *
 * **Validates: Req 14.6**
 *
 * Concurrently attempt to acquire the same lock key N times.
 * Assert that exactly 1 acquisition succeeds and the rest throw LOCK_CONFLICT.
 */
describe('RedisLockAdapter — Property 15: distributed lock exclusivity', () => {
  it('exactly 1 of 10 concurrent acquire() calls succeeds for the same key', async () => {
    /**
     * **Validates: Req 14.6**
     *
     * The in-memory Redis mock serialises SET NX operations synchronously,
     * which faithfully models the atomicity guarantee of Redis SET NX PX.
     * We fire 10 concurrent acquire() calls and assert exactly 1 wins.
     */
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 40 }).map((s) => `lock:prop15:${s}`),
        async (lockKey) => {
          const client = new InMemoryRedisClient();
          const adapter = buildAdapter(client);

          // 10 concurrent acquire attempts — no retries so each attempt is a single SET NX
          const results = await Promise.allSettled(
            Array.from({ length: 10 }, () =>
              adapter.acquire(lockKey, 5_000, { maxRetries: 0 }),
            ),
          );

          const fulfilled = results.filter((r) => r.status === 'fulfilled');
          const rejected = results.filter((r) => r.status === 'rejected');

          // Exactly one acquirer wins
          expect(fulfilled).toHaveLength(1);
          // All others get LOCK_CONFLICT
          expect(rejected).toHaveLength(9);

          for (const r of rejected) {
            expect((r as PromiseRejectedResult).reason).toMatchObject({
              code: 'LOCK_CONFLICT',
            });
          }

          // Clean up so the next iteration starts fresh
          client.forceDelete(lockKey);
        },
      ),
      { numRuns: 50 },
    );
  });

  it('exactly 1 of 10 concurrent acquire() calls succeeds across arbitrary concurrency counts', async () => {
    /**
     * **Validates: Req 14.6**
     *
     * Parameterises the number of concurrent callers (2–20) to ensure the
     * exclusivity property holds regardless of contention level.
     */
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 2, max: 20 }),
        async (concurrency) => {
          const client = new InMemoryRedisClient();
          const adapter = buildAdapter(client);
          const lockKey = `lock:prop15:concurrency:${concurrency}`;

          const results = await Promise.allSettled(
            Array.from({ length: concurrency }, () =>
              adapter.acquire(lockKey, 5_000, { maxRetries: 0 }),
            ),
          );

          const fulfilled = results.filter((r) => r.status === 'fulfilled');
          const rejected = results.filter((r) => r.status === 'rejected');

          expect(fulfilled).toHaveLength(1);
          expect(rejected).toHaveLength(concurrency - 1);

          client.forceDelete(lockKey);
        },
      ),
      { numRuns: 50 },
    );
  });
});

// ── Unit Tests: lock lifecycle ─────────────────────────────────────────────

describe('RedisLockAdapter — lock lifecycle', () => {
  let client: InMemoryRedisClient;
  let adapter: RedisLockAdapter;
  const KEY = 'lock:unit:test-key';

  beforeEach(() => {
    client = new InMemoryRedisClient();
    adapter = buildAdapter(client);
  });

  afterEach(() => {
    client.forceDelete(KEY);
  });

  it('acquire() returns a LockToken with the correct key', async () => {
    const token = await adapter.acquire(KEY, 5_000, { maxRetries: 0 });

    expect(token.key).toBe(KEY);
    expect(token.value).toBeTruthy();
    expect(token.ttlMs).toBe(5_000);
    expect(token.acquiredAt).toBeInstanceOf(Date);
  });

  it('release() removes the lock so a subsequent acquire() succeeds', async () => {
    const token = await adapter.acquire(KEY, 5_000, { maxRetries: 0 });
    expect(client.has(KEY)).toBe(true);

    await adapter.release(token);
    expect(client.has(KEY)).toBe(false);

    // A new acquire must succeed after release
    const token2 = await adapter.acquire(KEY, 5_000, { maxRetries: 0 });
    expect(token2.key).toBe(KEY);
  });

  it('release() with a wrong token value does not delete the lock (ownership check)', async () => {
    await adapter.acquire(KEY, 5_000, { maxRetries: 0 });

    const fakeToken: LockToken = {
      key: KEY,
      value: 'wrong-owner-uuid',
      acquiredAt: new Date(),
      ttlMs: 5_000,
    };

    // Should not throw — silently logs a warning
    await expect(adapter.release(fakeToken)).resolves.toBeUndefined();

    // Lock must still be held by the original owner
    expect(client.has(KEY)).toBe(true);
  });

  it('extend() succeeds when the token matches the stored owner', async () => {
    const token = await adapter.acquire(KEY, 5_000, { maxRetries: 0 });
    await expect(adapter.extend(token, 10_000)).resolves.toBeUndefined();
  });

  it('extend() throws LOCK_EXTEND_FAILED when the token does not match', async () => {
    await adapter.acquire(KEY, 5_000, { maxRetries: 0 });

    const fakeToken: LockToken = {
      key: KEY,
      value: 'wrong-owner-uuid',
      acquiredAt: new Date(),
      ttlMs: 5_000,
    };

    await expect(adapter.extend(fakeToken, 10_000)).rejects.toMatchObject({
      code: 'LOCK_EXTEND_FAILED',
    });
  });

  it('acquire() throws LOCK_CONFLICT after maxRetries exhausted', async () => {
    // Hold the lock so all retries fail
    await adapter.acquire(KEY, 60_000, { maxRetries: 0 });

    await expect(
      adapter.acquire(KEY, 5_000, { maxRetries: 2, retryDelayMs: 1 }),
    ).rejects.toMatchObject({ code: 'LOCK_CONFLICT' });
  });

  it('acquire() succeeds on retry when the lock is released between attempts', async () => {
    const firstToken = await adapter.acquire(KEY, 60_000, { maxRetries: 0 });

    // Release the lock after a short delay to allow the retry to succeed
    const releaseAfterDelay = new Promise<void>((resolve) => {
      setTimeout(async () => {
        await adapter.release(firstToken);
        resolve();
      }, 20);
    });

    const [, secondToken] = await Promise.all([
      releaseAfterDelay,
      adapter.acquire(KEY, 5_000, { maxRetries: 3, retryDelayMs: 10 }),
    ]);

    expect((secondToken as LockToken).key).toBe(KEY);
  });
});

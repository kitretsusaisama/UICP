import * as fc from 'fast-check';
import { IdempotencyService, IdempotencyRecord } from './idempotency.service';
import { ICachePort } from '../ports/driven/i-cache.port';

/**
 * Property-based tests for IdempotencyService.
 *
 * Covers:
 *   - Req 2.8: cache response for 24h; return cached response on replay
 *   - Property 14: two requests with the same idempotency key return identical responses
 */

/** Build an IdempotencyService with an in-memory mock ICachePort. */
function makeInMemoryCache(): ICachePort & { store: Map<string, string> } {
  const store = new Map<string, string>();

  return {
    store,
    get: jest.fn(async (key: string) => store.get(key) ?? null),
    set: jest.fn(async (key: string, value: string) => { store.set(key, value); }),
    del: jest.fn(async (key: string) => { store.delete(key); }),
    getdel: jest.fn(async (key: string) => {
      const value = store.get(key) ?? null;
      if (value !== null) store.delete(key);
      return value;
    }),
    sismember: jest.fn(async () => false),
    sadd: jest.fn(async () => 0),
    srem: jest.fn(async () => 0),
    smembers: jest.fn(async () => []),
    incr: jest.fn(async () => 0),
    expire: jest.fn(async () => true),
  };
}

function makeService(cache: ICachePort): IdempotencyService {
  return new IdempotencyService(cache as any);
}

/** Arbitrary for a minimal IdempotencyRecord (without createdAt, which is added by store()). */
const recordArb = fc.record({
  statusCode: fc.integer({ min: 200, max: 599 }),
  body: fc.oneof(
    fc.string(),
    fc.record({ id: fc.uuid(), message: fc.string() }),
  ),
  headers: fc.option(
    fc.dictionary(fc.string({ minLength: 1, maxLength: 20 }), fc.string()),
    { nil: undefined },
  ),
});

const TENANT_ID = 'tenant-test-001';

describe('IdempotencyService', () => {
  describe('check() / store() — basic round-trip', () => {
    it('returns null when no record has been stored', async () => {
      const svc = makeService(makeInMemoryCache());
      const result = await svc.check(TENANT_ID, 'non-existent-key');
      expect(result).toBeNull();
    });

    it('returns the stored record after store() is called', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);
      const record = { statusCode: 200, body: { id: 'abc' } };

      await svc.store(TENANT_ID, 'key-1', record);
      const result = await svc.check(TENANT_ID, 'key-1');

      expect(result).not.toBeNull();
      expect(result!.statusCode).toBe(200);
      expect(result!.body).toEqual({ id: 'abc' });
    });

    it('stores with 24h TTL (86400 seconds)', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);

      await svc.store(TENANT_ID, 'key-ttl', { statusCode: 201, body: 'created' });

      expect(cache.set).toHaveBeenCalledWith(
        `idempotency:${TENANT_ID}:key-ttl`,
        expect.any(String),
        86_400,
      );
    });
  });

  describe('isReplay()', () => {
    it('returns false when no record exists', async () => {
      const svc = makeService(makeInMemoryCache());
      expect(await svc.isReplay(TENANT_ID, 'missing-key')).toBe(false);
    });

    it('returns true after a record has been stored', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);

      await svc.store(TENANT_ID, 'replay-key', { statusCode: 200, body: 'ok' });
      expect(await svc.isReplay(TENANT_ID, 'replay-key')).toBe(true);
    });
  });

  /**
   * Property 14: Two requests with the same idempotency key return identical responses.
   *
   * **Validates: Requirements 2.8**
   *
   * Procedure:
   *   1. store(key, record)  — simulates first request completing
   *   2. check(key)          — simulates second request hitting the cache
   *   3. Assert the retrieved record body and statusCode are identical to what was stored
   *   4. Assert isReplay() returns true (second request is a replay)
   */
  describe('Property 14 — idempotency consistency (Req 2.8)', () => {
    it('store then check returns identical body and statusCode for any uuid key', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.uuid(),
          recordArb,
          async (idempotencyKey, record) => {
            const cache = makeInMemoryCache();
            const svc = makeService(cache);

            // First request: store the response
            await svc.store(TENANT_ID, idempotencyKey, record);

            // Second request: retrieve the cached response
            const replayed = await svc.check(TENANT_ID, idempotencyKey);

            expect(replayed).not.toBeNull();
            expect(replayed!.statusCode).toBe(record.statusCode);
            expect(replayed!.body).toEqual(record.body);
          },
        ),
        { numRuns: 100 },
      );
    });

    it('isReplay() returns true after store() for any uuid key', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.uuid(),
          recordArb,
          async (idempotencyKey, record) => {
            const cache = makeInMemoryCache();
            const svc = makeService(cache);

            // Before store: not a replay
            expect(await svc.isReplay(TENANT_ID, idempotencyKey)).toBe(false);

            // After store: is a replay
            await svc.store(TENANT_ID, idempotencyKey, record);
            expect(await svc.isReplay(TENANT_ID, idempotencyKey)).toBe(true);
          },
        ),
        { numRuns: 100 },
      );
    });

    it('replayed response carries x-idempotency-replayed: true header marker', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.uuid(),
          recordArb,
          async (idempotencyKey, record) => {
            const cache = makeInMemoryCache();
            const svc = makeService(cache);

            // Store with the replay header included (as the interceptor would do)
            const recordWithReplayHeader = {
              ...record,
              headers: {
                ...(record.headers ?? {}),
                'x-idempotency-replayed': 'true',
              },
            };

            await svc.store(TENANT_ID, idempotencyKey, recordWithReplayHeader);

            const replayed = await svc.check(TENANT_ID, idempotencyKey);

            expect(replayed).not.toBeNull();
            expect(replayed!.headers?.['x-idempotency-replayed']).toBe('true');
          },
        ),
        { numRuns: 100 },
      );
    });

    it('different keys are stored and retrieved independently', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.tuple(fc.uuid(), fc.uuid()),
          fc.tuple(recordArb, recordArb),
          async ([key1, key2], [record1, record2]) => {
            fc.pre(key1 !== key2);

            const cache = makeInMemoryCache();
            const svc = makeService(cache);

            await svc.store(TENANT_ID, key1, record1);
            await svc.store(TENANT_ID, key2, record2);

            const result1 = await svc.check(TENANT_ID, key1);
            const result2 = await svc.check(TENANT_ID, key2);

            expect(result1!.statusCode).toBe(record1.statusCode);
            expect(result2!.statusCode).toBe(record2.statusCode);
            expect(result1!.body).toEqual(record1.body);
            expect(result2!.body).toEqual(record2.body);
          },
        ),
        { numRuns: 50 },
      );
    });

    it('keys are tenant-scoped: same idempotency key under different tenants are independent', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.uuid(),
          fc.tuple(
            fc.uuid(), // tenantId1
            fc.uuid(), // tenantId2
          ),
          fc.tuple(recordArb, recordArb),
          async (idempotencyKey, [tenantId1, tenantId2], [record1, record2]) => {
            // Skip when tenants happen to be equal (extremely rare with uuid)
            fc.pre(tenantId1 !== tenantId2);

            const cache = makeInMemoryCache();
            const svc = makeService(cache);

            await svc.store(tenantId1, idempotencyKey, record1);
            await svc.store(tenantId2, idempotencyKey, record2);

            const result1 = await svc.check(tenantId1, idempotencyKey);
            const result2 = await svc.check(tenantId2, idempotencyKey);

            expect(result1!.statusCode).toBe(record1.statusCode);
            expect(result2!.statusCode).toBe(record2.statusCode);
          },
        ),
        { numRuns: 50 },
      );
    });
  });
});

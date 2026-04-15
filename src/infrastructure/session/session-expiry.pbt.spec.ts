/**
 * Property-Based Test — Session Expiry (Property 9)
 *
 * **Property 9: t > session.expiresAt ⟹ findById(session.id) = null**
 *
 * **Validates: Req 8.1**
 *
 * For any session with any TTL, once the current time advances past
 * `expiresAt`, `findById()` must return null — the session is gone.
 *
 * Strategy: Use the in-memory Redis mock from redis-session.store.spec.ts
 * (inlined here for isolation) with jest fake timers to control time.
 */

import * as fc from 'fast-check';
import { RedisSessionStore } from './redis-session.store';
import { Session } from '../../domain/aggregates/session.aggregate';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { UserId } from '../../domain/value-objects/user-id.vo';

// ── Minimal in-memory Redis mock ───────────────────────────────────────────

class InMemoryRedisClient {
  private readonly hashes = new Map<string, Record<string, string>>();
  private readonly sortedSets = new Map<string, Map<string, number>>();
  private readonly ttls = new Map<string, number>();

  private isExpired(key: string): boolean {
    const exp = this.ttls.get(key);
    return exp !== undefined && Date.now() >= exp;
  }

  private evict(key: string): void {
    if (this.isExpired(key)) {
      this.hashes.delete(key);
      this.sortedSets.delete(key);
      this.ttls.delete(key);
    }
  }

  ttl(key: string): number {
    this.evict(key);
    if (!this.hashes.has(key) && !this.sortedSets.has(key)) return -2;
    const exp = this.ttls.get(key);
    return exp === undefined ? -1 : Math.ceil((exp - Date.now()) / 1000);
  }

  async hset(key: string, fields: Record<string, string> | string, value?: string): Promise<number> {
    this.evict(key);
    const existing = this.hashes.get(key) ?? {};
    if (typeof fields === 'string' && value !== undefined) existing[fields] = value;
    else if (typeof fields === 'object') Object.assign(existing, fields);
    this.hashes.set(key, existing);
    return 1;
  }

  async hgetall(key: string): Promise<Record<string, string> | null> {
    this.evict(key);
    const data = this.hashes.get(key);
    return data ? { ...data } : null;
  }

  async hget(key: string, field: string): Promise<string | null> {
    this.evict(key);
    return this.hashes.get(key)?.[field] ?? null;
  }

  async expire(key: string, ttlSeconds: number): Promise<number> {
    this.evict(key);
    if (!this.hashes.has(key) && !this.sortedSets.has(key)) return 0;
    this.ttls.set(key, Date.now() + ttlSeconds * 1000);
    return 1;
  }

  async del(key: string): Promise<number> {
    const existed = this.hashes.has(key) || this.sortedSets.has(key);
    this.hashes.delete(key);
    this.sortedSets.delete(key);
    this.ttls.delete(key);
    return existed ? 1 : 0;
  }

  async zadd(key: string, score: number, member: string): Promise<number> {
    const set = this.sortedSets.get(key) ?? new Map<string, number>();
    const isNew = !set.has(member);
    set.set(member, score);
    this.sortedSets.set(key, set);
    return isNew ? 1 : 0;
  }

  async zcard(key: string): Promise<number> {
    return this.sortedSets.get(key)?.size ?? 0;
  }

  async zrange(key: string, start: number, stop: number): Promise<string[]> {
    const set = this.sortedSets.get(key);
    if (!set) return [];
    const sorted = [...set.entries()].sort((a, b) => a[1] - b[1]).map(([m]) => m);
    const end = stop === -1 ? sorted.length : stop + 1;
    return sorted.slice(start, end);
  }

  async zrem(key: string, member: string): Promise<number> {
    const set = this.sortedSets.get(key);
    if (!set) return 0;
    return set.delete(member) ? 1 : 0;
  }

  pipeline(): PipelineMock {
    return new PipelineMock(this);
  }
}

class PipelineMock {
  private readonly cmds: Array<() => Promise<[null, unknown]>> = [];
  constructor(private readonly c: InMemoryRedisClient) {}
  hset(k: string, f: Record<string, string> | string, v?: string): this {
    this.cmds.push(async () => [null, await this.c.hset(k, f as any, v)]);
    return this;
  }
  expire(k: string, s: number): this {
    this.cmds.push(async () => [null, await this.c.expire(k, s)]);
    return this;
  }
  zadd(k: string, score: number, m: string): this {
    this.cmds.push(async () => [null, await this.c.zadd(k, score, m)]);
    return this;
  }
  del(k: string): this {
    this.cmds.push(async () => [null, await this.c.del(k)]);
    return this;
  }
  zrem(k: string, m: string): this {
    this.cmds.push(async () => [null, await this.c.zrem(k, m)]);
    return this;
  }
  hgetall(k: string): this {
    this.cmds.push(async () => [null, await this.c.hgetall(k)]);
    return this;
  }
  async exec(): Promise<Array<[null, unknown]>> {
    const results: Array<[null, unknown]> = [];
    for (const cmd of this.cmds) results.push(await cmd());
    return results;
  }
}

function buildStore(client: InMemoryRedisClient): RedisSessionStore {
  return new RedisSessionStore({ getClient: () => client, isCircuitOpen: () => false } as any);
}

function makeSession(tenantId: TenantId, userId: UserId, ttlSeconds: number): Session {
  return Session.create({ tenantId, userId, ipHash: 'abc', uaBrowser: 'Chrome', uaOs: 'Linux', uaDeviceType: 'desktop', ttlSeconds });
}

// ── Property 9 ─────────────────────────────────────────────────────────────

describe('Property 9 — Session expiry: t > expiresAt ⟹ findById = null (Req 8.1)', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  /**
   * Core property: for any TTL in [1, 3600] seconds, advancing time past
   * the TTL causes findById() to return null.
   */
  it('findById() returns null after TTL elapses for any TTL value', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 3600 }),
        async (ttlSeconds) => {
          const client = new InMemoryRedisClient();
          const store = buildStore(client);
          const tenantId = TenantId.create();
          const userId = UserId.create();

          const session = makeSession(tenantId, userId, ttlSeconds);
          await store.create(session, ttlSeconds);

          // Confirm session exists before expiry
          const before = await store.findById(session.id, tenantId);
          expect(before).not.toBeNull();

          // Advance time past the TTL
          jest.advanceTimersByTime((ttlSeconds + 1) * 1000);

          // Session must be gone
          const after = await store.findById(session.id, tenantId);
          expect(after).toBeNull();
        },
      ),
      { numRuns: 100 },
    );
  });

  it('findById() returns the session when time has NOT yet passed expiresAt', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 10, max: 3600 }),
        fc.integer({ min: 1, max: 9 }),
        async (ttlSeconds, elapsedSeconds) => {
          // elapsedSeconds < ttlSeconds — session should still be alive
          fc.pre(elapsedSeconds < ttlSeconds);

          const client = new InMemoryRedisClient();
          const store = buildStore(client);
          const tenantId = TenantId.create();
          const userId = UserId.create();

          const session = makeSession(tenantId, userId, ttlSeconds);
          await store.create(session, ttlSeconds);

          // Advance time but stay within TTL
          jest.advanceTimersByTime(elapsedSeconds * 1000);

          const found = await store.findById(session.id, tenantId);
          expect(found).not.toBeNull();
          expect(found!.id.toString()).toBe(session.id.toString());
        },
      ),
      { numRuns: 100 },
    );
  });

  it('multiple sessions with different TTLs expire independently', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 5 }),    // short TTL (expires first)
        fc.integer({ min: 10, max: 3600 }), // long TTL (survives)
        async (shortTtl, longTtl) => {
          fc.pre(shortTtl < longTtl);

          const client = new InMemoryRedisClient();
          const store = buildStore(client);
          const tenantId = TenantId.create();
          const userId = UserId.create();

          const shortSession = makeSession(tenantId, userId, shortTtl);
          const longSession = makeSession(tenantId, userId, longTtl);

          await store.create(shortSession, shortTtl);
          await store.create(longSession, longTtl);

          // Advance past the short TTL but not the long one
          jest.advanceTimersByTime((shortTtl + 1) * 1000);

          expect(await store.findById(shortSession.id, tenantId)).toBeNull();
          expect(await store.findById(longSession.id, tenantId)).not.toBeNull();
        },
      ),
      { numRuns: 50 },
    );
  });
});

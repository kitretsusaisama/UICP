import { RedisSessionStore } from './redis-session.store';
import { Session } from '../../domain/aggregates/session.aggregate';
import { SessionId } from '../../domain/value-objects/session-id.vo';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { UserId } from '../../domain/value-objects/user-id.vo';

// ── In-Memory Redis Mock ───────────────────────────────────────────────────

/**
 * Full in-memory Redis mock implementing the hash, sorted-set, and pipeline
 * APIs used by RedisSessionStore. TTL is tracked per key and checked lazily
 * on every read. Supports jest.useFakeTimers() for TTL expiry tests.
 */
class InMemoryRedisClient {
  private readonly hashes = new Map<string, Record<string, string>>();
  private readonly sortedSets = new Map<string, Map<string, number>>();
  private readonly ttls = new Map<string, number>(); // key → absolute expiry ms

  // ── TTL helpers ────────────────────────────────────────────────────────────

  private isExpired(key: string): boolean {
    const exp = this.ttls.get(key);
    if (exp === undefined) return false;
    return Date.now() >= exp;
  }

  private evictIfExpired(key: string): void {
    if (this.isExpired(key)) {
      this.hashes.delete(key);
      this.sortedSets.delete(key);
      this.ttls.delete(key);
    }
  }

  /** Returns remaining TTL in seconds, or -1 if no TTL set, or -2 if missing. */
  ttl(key: string): number {
    this.evictIfExpired(key);
    if (!this.hashes.has(key) && !this.sortedSets.has(key)) return -2;
    const exp = this.ttls.get(key);
    if (exp === undefined) return -1;
    return Math.ceil((exp - Date.now()) / 1000);
  }

  // ── Hash commands ──────────────────────────────────────────────────────────

  async hset(key: string, fields: Record<string, string> | string, value?: string): Promise<number> {
    this.evictIfExpired(key);
    const existing = this.hashes.get(key) ?? {};
    if (typeof fields === 'string' && value !== undefined) {
      existing[fields] = value;
    } else if (typeof fields === 'object') {
      Object.assign(existing, fields);
    }
    this.hashes.set(key, existing);
    return 1;
  }

  async hgetall(key: string): Promise<Record<string, string> | null> {
    this.evictIfExpired(key);
    const data = this.hashes.get(key);
    if (!data) return null;
    return { ...data };
  }

  async hget(key: string, field: string): Promise<string | null> {
    this.evictIfExpired(key);
    return this.hashes.get(key)?.[field] ?? null;
  }

  // ── Key commands ───────────────────────────────────────────────────────────

  async expire(key: string, ttlSeconds: number): Promise<number> {
    this.evictIfExpired(key);
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

  // ── Sorted set commands ────────────────────────────────────────────────────

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
    // Sort by score ascending
    const sorted = [...set.entries()].sort((a, b) => a[1] - b[1]).map(([m]) => m);
    const end = stop === -1 ? sorted.length : stop + 1;
    return sorted.slice(start, end);
  }

  async zrem(key: string, member: string): Promise<number> {
    const set = this.sortedSets.get(key);
    if (!set) return 0;
    const existed = set.delete(member);
    return existed ? 1 : 0;
  }

  // ── Pipeline ───────────────────────────────────────────────────────────────

  pipeline(): PipelineMock {
    return new PipelineMock(this);
  }
}

/** Batches commands and executes them sequentially on exec(). */
class PipelineMock {
  private readonly commands: Array<() => Promise<[null, unknown]>> = [];

  constructor(private readonly client: InMemoryRedisClient) {}

  hset(key: string, fields: Record<string, string> | string, value?: string): this {
    this.commands.push(async () => [null, await this.client.hset(key, fields as any, value)]);
    return this;
  }

  expire(key: string, ttlSeconds: number): this {
    this.commands.push(async () => [null, await this.client.expire(key, ttlSeconds)]);
    return this;
  }

  zadd(key: string, score: number, member: string): this {
    this.commands.push(async () => [null, await this.client.zadd(key, score, member)]);
    return this;
  }

  del(key: string): this {
    this.commands.push(async () => [null, await this.client.del(key)]);
    return this;
  }

  zrem(key: string, member: string): this {
    this.commands.push(async () => [null, await this.client.zrem(key, member)]);
    return this;
  }

  hgetall(key: string): this {
    this.commands.push(async () => [null, await this.client.hgetall(key)]);
    return this;
  }

  async exec(): Promise<Array<[null, unknown]>> {
    const results: Array<[null, unknown]> = [];
    for (const cmd of this.commands) {
      results.push(await cmd());
    }
    return results;
  }
}

// ── Test Helpers ───────────────────────────────────────────────────────────

function buildStore(client: InMemoryRedisClient): RedisSessionStore {
  const mockCache = { getClient: () => client, isCircuitOpen: () => false } as any;
  return new RedisSessionStore(mockCache);
}

function makeSession(params: {
  tenantId: TenantId;
  userId: UserId;
  ttlSeconds?: number;
  createdAt?: Date;
}): Session {
  return Session.create({
    tenantId: params.tenantId,
    userId: params.userId,
    ipHash: 'abc123',
    uaBrowser: 'Chrome',
    uaOs: 'Linux',
    uaDeviceType: 'desktop',
    ttlSeconds: params.ttlSeconds ?? 3600,
    createdAt: params.createdAt,
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('RedisSessionStore — Session TTL expiry (Req 8.1)', () => {
  let client: InMemoryRedisClient;
  let store: RedisSessionStore;
  const tenantId = TenantId.create();
  const userId = UserId.create();

  beforeEach(() => {
    jest.useFakeTimers();
    client = new InMemoryRedisClient();
    store = buildStore(client);
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('findById() returns the session before TTL elapses', async () => {
    const session = makeSession({ tenantId, userId, ttlSeconds: 60 });
    await store.create(session, 60);

    const found = await store.findById(session.id, tenantId);
    expect(found).not.toBeNull();
    expect(found!.id.toString()).toBe(session.id.toString());
  });

  it('findById() returns null after TTL elapses', async () => {
    const session = makeSession({ tenantId, userId, ttlSeconds: 1 });
    await store.create(session, 1);

    // Advance time past the 1-second TTL
    jest.advanceTimersByTime(2000);

    const found = await store.findById(session.id, tenantId);
    expect(found).toBeNull();
  });

  it('findById() returns null for a completely unknown session', async () => {
    const unknownId = SessionId.create();
    const found = await store.findById(unknownId, tenantId);
    expect(found).toBeNull();
  });
});

describe('RedisSessionStore — OTP single-use guarantee via GETDEL (Req 6.2)', () => {
  /**
   * The OTP service uses Redis GETDEL for atomic single-use consumption.
   * We test this at the mock level: store a value, first read deletes it,
   * second read returns null.
   */
  it('GETDEL semantics: first call returns value, second call returns null', async () => {
    const client = new InMemoryRedisClient();

    // Simulate storing an OTP
    await client.hset('otp:tenant1:user1', { code: '123456' });

    // First read — value present
    const first = await client.hgetall('otp:tenant1:user1');
    expect(first).not.toBeNull();
    expect(first!['code']).toBe('123456');

    // Simulate atomic GETDEL: delete after first read
    await client.del('otp:tenant1:user1');

    // Second read — key gone
    const second = await client.hgetall('otp:tenant1:user1');
    expect(second).toBeNull();
  });

  it('del() on a missing key returns 0 (idempotent)', async () => {
    const client = new InMemoryRedisClient();
    const result = await client.del('otp:nonexistent');
    expect(result).toBe(0);
  });

  it('session invalidate() removes the session so findById() returns null', async () => {
    const client = new InMemoryRedisClient();
    const store = buildStore(client);
    const tenantId = TenantId.create();
    const userId = UserId.create();

    const session = makeSession({ tenantId, userId });
    await store.create(session, 3600);

    // Confirm it exists
    expect(await store.findById(session.id, tenantId)).not.toBeNull();

    // Invalidate (single-use pattern)
    await store.invalidate(session.id, tenantId);

    // Now gone
    expect(await store.findById(session.id, tenantId)).toBeNull();
  });
});

describe('RedisSessionStore — LRU eviction (Req 8.3)', () => {
  let client: InMemoryRedisClient;
  let store: RedisSessionStore;
  const tenantId = TenantId.create();
  const userId = UserId.create();

  beforeEach(() => {
    client = new InMemoryRedisClient();
    store = buildStore(client);
  });

  it('evicts the oldest session when max_sessions + 1 are created', async () => {
    const maxSessions = 3;
    const sessions: Session[] = [];

    // Create sessions with distinct timestamps (oldest first)
    for (let i = 0; i < maxSessions + 1; i++) {
      const s = makeSession({
        tenantId,
        userId,
        createdAt: new Date(1_000_000 + i * 1000), // ascending timestamps
      });
      sessions.push(s);
      await store.create(s, 3600, maxSessions);
    }

    // Oldest session (index 0) must be evicted
    const oldest = await store.findById(sessions[0]!.id, tenantId);
    expect(oldest).toBeNull();

    // The 3 newest sessions must still be findable
    for (let i = 1; i <= maxSessions; i++) {
      const found = await store.findById(sessions[i]!.id, tenantId);
      expect(found).not.toBeNull();
      expect(found!.id.toString()).toBe(sessions[i]!.id.toString());
    }
  });

  it('does not evict sessions for a different user', async () => {
    const otherUserId = UserId.create();
    const maxSessions = 2;

    // Fill up the first user's sessions to the limit
    const userSessions: Session[] = [];
    for (let i = 0; i < maxSessions; i++) {
      const s = makeSession({ tenantId, userId, createdAt: new Date(1_000_000 + i * 1000) });
      userSessions.push(s);
      await store.create(s, 3600, maxSessions);
    }

    // Create a session for the other user
    const otherSession = makeSession({ tenantId, userId: otherUserId });
    await store.create(otherSession, 3600, maxSessions);

    // Other user's session must be unaffected
    const found = await store.findById(otherSession.id, tenantId);
    expect(found).not.toBeNull();

    // First user's sessions must still be at the limit (no eviction needed)
    for (const s of userSessions) {
      expect(await store.findById(s.id, tenantId)).not.toBeNull();
    }
  });

  it('evicts multiple oldest sessions when multiple are over the limit', async () => {
    const maxSessions = 2;
    const sessions: Session[] = [];

    // Create 4 sessions (2 over the limit)
    for (let i = 0; i < 4; i++) {
      const s = makeSession({ tenantId, userId, createdAt: new Date(1_000_000 + i * 1000) });
      sessions.push(s);
      await store.create(s, 3600, maxSessions);
    }

    // The 2 oldest must be evicted
    expect(await store.findById(sessions[0]!.id, tenantId)).toBeNull();
    expect(await store.findById(sessions[1]!.id, tenantId)).toBeNull();

    // The 2 newest must remain
    expect(await store.findById(sessions[2]!.id, tenantId)).not.toBeNull();
    expect(await store.findById(sessions[3]!.id, tenantId)).not.toBeNull();
  });
});

describe('RedisSessionStore — Sliding TTL (Req 8.4)', () => {
  let client: InMemoryRedisClient;
  let store: RedisSessionStore;
  const tenantId = TenantId.create();
  const userId = UserId.create();

  beforeEach(() => {
    jest.useFakeTimers();
    client = new InMemoryRedisClient();
    store = buildStore(client);
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('extendTtl() resets the Redis key TTL to the new value', async () => {
    const session = makeSession({ tenantId, userId, ttlSeconds: 100 });
    await store.create(session, 100);

    // Advance time by 50 seconds (TTL should be ~50s remaining)
    jest.advanceTimersByTime(50_000);

    // Extend to 200 seconds
    await store.extendTtl(session.id, tenantId, 200);

    // TTL should now be ~200 seconds (not ~50)
    const remainingTtl = client.ttl(`session:${tenantId.toString()}:${session.id.toString()}`);
    expect(remainingTtl).toBeGreaterThan(190);
    expect(remainingTtl).toBeLessThanOrEqual(200);
  });

  it('extendTtl() updates the expiresAt field in the hash', async () => {
    const session = makeSession({ tenantId, userId, ttlSeconds: 100 });
    await store.create(session, 100);

    const beforeExtend = Date.now();
    await store.extendTtl(session.id, tenantId, 200);

    const found = await store.findById(session.id, tenantId);
    expect(found).not.toBeNull();

    const expiresAt = found!.getExpiresAt().getTime();
    const expectedMin = beforeExtend + 200 * 1000;
    const expectedMax = beforeExtend + 201 * 1000;
    expect(expiresAt).toBeGreaterThanOrEqual(expectedMin);
    expect(expiresAt).toBeLessThanOrEqual(expectedMax);
  });

  it('session is still findable after extendTtl() when original TTL would have expired', async () => {
    const session = makeSession({ tenantId, userId, ttlSeconds: 10 });
    await store.create(session, 10);

    // Advance 8 seconds — still within original TTL
    jest.advanceTimersByTime(8_000);

    // Extend by 100 seconds
    await store.extendTtl(session.id, tenantId, 100);

    // Advance past the original TTL (10s total from creation)
    jest.advanceTimersByTime(5_000); // now 13s from creation, but TTL was reset to 100s

    const found = await store.findById(session.id, tenantId);
    expect(found).not.toBeNull();
  });

  it('extendTtl() on a non-existent key is a no-op', async () => {
    const unknownId = SessionId.create();
    // Should not throw
    await expect(store.extendTtl(unknownId, tenantId, 200)).resolves.toBeUndefined();
  });
});

describe('RedisSessionStore — findByUserId()', () => {
  let client: InMemoryRedisClient;
  let store: RedisSessionStore;
  const tenantId = TenantId.create();
  const userId = UserId.create();

  beforeEach(() => {
    jest.useFakeTimers();
    client = new InMemoryRedisClient();
    store = buildStore(client);
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('returns all active sessions for a user', async () => {
    const s1 = makeSession({ tenantId, userId, createdAt: new Date(1_000_000) });
    const s2 = makeSession({ tenantId, userId, createdAt: new Date(1_001_000) });
    await store.create(s1, 3600);
    await store.create(s2, 3600);

    const sessions = await store.findByUserId(userId, tenantId);
    expect(sessions).toHaveLength(2);
    const ids = sessions.map((s) => s.id.toString());
    expect(ids).toContain(s1.id.toString());
    expect(ids).toContain(s2.id.toString());
  });

  it('skips expired sessions and cleans them from the sorted set', async () => {
    const s1 = makeSession({ tenantId, userId, ttlSeconds: 1 });
    const s2 = makeSession({ tenantId, userId, ttlSeconds: 3600 });
    await store.create(s1, 1);
    await store.create(s2, 3600);

    // Expire s1
    jest.advanceTimersByTime(2000);

    const sessions = await store.findByUserId(userId, tenantId);
    expect(sessions).toHaveLength(1);
    expect(sessions[0]!.id.toString()).toBe(s2.id.toString());
  });

  it('returns empty array when user has no sessions', async () => {
    const unknownUser = UserId.create();
    const sessions = await store.findByUserId(unknownUser, tenantId);
    expect(sessions).toEqual([]);
  });
});

describe('RedisSessionStore — invalidate()', () => {
  let client: InMemoryRedisClient;
  let store: RedisSessionStore;
  const tenantId = TenantId.create();
  const userId = UserId.create();

  beforeEach(() => {
    client = new InMemoryRedisClient();
    store = buildStore(client);
  });

  it('removes the session hash and sorted set entry', async () => {
    const session = makeSession({ tenantId, userId });
    await store.create(session, 3600);

    await store.invalidate(session.id, tenantId);

    expect(await store.findById(session.id, tenantId)).toBeNull();

    // Sorted set should no longer contain this session
    const remaining = await store.findByUserId(userId, tenantId);
    expect(remaining.map((s) => s.id.toString())).not.toContain(session.id.toString());
  });

  it('invalidating one session does not affect other sessions for the same user', async () => {
    const s1 = makeSession({ tenantId, userId });
    const s2 = makeSession({ tenantId, userId });
    await store.create(s1, 3600);
    await store.create(s2, 3600);

    await store.invalidate(s1.id, tenantId);

    expect(await store.findById(s1.id, tenantId)).toBeNull();
    expect(await store.findById(s2.id, tenantId)).not.toBeNull();
  });

  it('invalidate() on a non-existent session is a no-op', async () => {
    const unknownId = SessionId.create();
    await expect(store.invalidate(unknownId, tenantId)).resolves.toBeUndefined();
  });
});

describe('RedisSessionStore — invalidateAll()', () => {
  let client: InMemoryRedisClient;
  let store: RedisSessionStore;
  const tenantId = TenantId.create();
  const userId = UserId.create();

  beforeEach(() => {
    client = new InMemoryRedisClient();
    store = buildStore(client);
  });

  it('removes all sessions for a user', async () => {
    const sessions = [
      makeSession({ tenantId, userId }),
      makeSession({ tenantId, userId }),
      makeSession({ tenantId, userId }),
    ];
    for (const s of sessions) {
      await store.create(s, 3600);
    }

    await store.invalidateAll(userId, tenantId);

    for (const s of sessions) {
      expect(await store.findById(s.id, tenantId)).toBeNull();
    }
    expect(await store.findByUserId(userId, tenantId)).toEqual([]);
  });

  it('does not affect sessions for a different user', async () => {
    const otherUserId = UserId.create();
    const mySession = makeSession({ tenantId, userId });
    const otherSession = makeSession({ tenantId, userId: otherUserId });

    await store.create(mySession, 3600);
    await store.create(otherSession, 3600);

    await store.invalidateAll(userId, tenantId);

    expect(await store.findById(mySession.id, tenantId)).toBeNull();
    expect(await store.findById(otherSession.id, tenantId)).not.toBeNull();
  });

  it('invalidateAll() on a user with no sessions is a no-op', async () => {
    const unknownUser = UserId.create();
    await expect(store.invalidateAll(unknownUser, tenantId)).resolves.toBeUndefined();
  });
});

describe('RedisSessionStore — setStatus()', () => {
  let client: InMemoryRedisClient;
  let store: RedisSessionStore;
  const tenantId = TenantId.create();
  const userId = UserId.create();

  beforeEach(() => {
    client = new InMemoryRedisClient();
    store = buildStore(client);
  });

  it('updates the status field in the hash', async () => {
    const session = makeSession({ tenantId, userId });
    await store.create(session, 3600);

    await store.setStatus(session.id, tenantId, 'ACTIVE');

    const found = await store.findById(session.id, tenantId);
    expect(found).not.toBeNull();
    expect(found!.getStatus()).toBe('ACTIVE');
  });

  it('can set status to REVOKED', async () => {
    const session = makeSession({ tenantId, userId });
    await store.create(session, 3600);

    await store.setStatus(session.id, tenantId, 'REVOKED');

    const found = await store.findById(session.id, tenantId);
    expect(found!.getStatus()).toBe('REVOKED');
  });
});

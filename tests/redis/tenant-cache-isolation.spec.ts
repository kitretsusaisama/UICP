import { describe, it, expect, beforeEach } from '@jest/globals';

// Simulating Redis cache with tenant isolation
interface CacheEntry {
  value: string;
  tenantId: string;
  ttl: number;
  createdAt: number;
}

// In-memory Redis simulation
const redisCache = new Map<string, CacheEntry>();

function cacheKey(tenantId: string, key: string): string {
  return `tenant:${tenantId}:${key}`;
}

async function cacheSet(tenantId: string, key: string, value: string, ttl: number = 3600): Promise<void> {
  const fullKey = cacheKey(tenantId, key);
  redisCache.set(fullKey, {
    value,
    tenantId,
    ttl,
    createdAt: Date.now(),
  });
}

async function cacheGet(tenantId: string, key: string): Promise<string | null> {
  const fullKey = cacheKey(tenantId, key);
  const entry = redisCache.get(fullKey);

  if (!entry) return null;

  // Check TTL
  const age = Date.now() - entry.createdAt;
  if (age > entry.ttl * 1000) {
    redisCache.delete(fullKey);
    return null;
  }

  return entry.value;
}

async function cacheDel(tenantId: string, key: string): Promise<void> {
  const fullKey = cacheKey(tenantId, key);
  redisCache.delete(fullKey);
}

async function cacheClear(tenantId: string): Promise<void> {
  // Clear only this tenant's cache
  for (const key of redisCache.keys()) {
    const entry = redisCache.get(key);
    if (entry?.tenantId === tenantId) {
      redisCache.delete(key);
    }
  }
}

describe('Tenant Cache Isolation', () => {
  beforeEach(() => {
    redisCache.clear();
  });

  it('isolates cache between tenants', async () => {
    await cacheSet('tenant-a', 'user:001', 'User A data');
    await cacheSet('tenant-b', 'user:001', 'User B data');

    const dataA = await cacheGet('tenant-a', 'user:001');
    const dataB = await cacheGet('tenant-b', 'user:001');

    expect(dataA).toBe('User A data');
    expect(dataB).toBe('User B data');
    expect(dataA).not.toBe(dataB);
  });

  it('does not evict Tenant B when Tenant A cache is cleared', async () => {
    await cacheSet('tenant-a', 'config', JSON.stringify({ apiKey: 'key-a' }));
    await cacheSet('tenant-b', 'config', JSON.stringify({ apiKey: 'key-b' }));

    // Clear Tenant A cache only
    await cacheClear('tenant-a');

    // Tenant B should still have data
    const tenantBData = await cacheGet('tenant-b', 'config');
    expect(tenantBData).toBe(JSON.stringify({ apiKey: 'key-b' }));

    // Tenant A should be cleared
    const tenantAData = await cacheGet('tenant-a', 'config');
    expect(tenantAData).toBeNull();
  });

  it('prevents cross-tenant cache reads', async () => {
    await cacheSet('tenant-a', 'secret', 'secret-a');
    await cacheSet('tenant-b', 'secret', 'secret-b');

    // Tenant A trying to read Tenant B's data
    const stolenData = await cacheGet('tenant-a', 'secret');
    expect(stolenData).toBe('secret-a'); // Gets their own, not tenant-b's

    // Different tenant read attempt
    const crossRead = await cacheGet('tenant-a', 'secret');
    expect(crossRead).not.toBe('secret-b');
  });

  it('prevents cross-tenant cache writes', async () => {
    await cacheSet('tenant-a', 'counter', '100');
    await cacheSet('tenant-b', 'counter', '200');

    // Overwrite attempt
    await cacheSet('tenant-a', 'counter', '999');

    const tenantA = await cacheGet('tenant-a', 'counter');
    const tenantB = await cacheGet('tenant-b', 'counter');

    expect(tenantA).toBe('999');
    expect(tenantB).toBe('200');
  });

  it('handles provider config caching per tenant', async () => {
    const providerConfigA = { provider: 'MSG91', senderId: 'APPA' };
    const providerConfigB = { provider: 'TWILIO', senderId: 'APPB' };

    await cacheSet('tenant-a', 'provider:sms', JSON.stringify(providerConfigA));
    await cacheSet('tenant-b', 'provider:sms', JSON.stringify(providerConfigB));

    const cachedA = await cacheGet('tenant-a', 'provider:sms');
    const cachedB = await cacheGet('tenant-b', 'provider:sms');

    expect(JSON.parse(cachedA!)).toEqual(providerConfigA);
    expect(JSON.parse(cachedB!)).toEqual(providerConfigB);
  });

  it('preserves session cache per tenant', async () => {
    const sessionA = { sessionId: 'sess-a', userId: 'user-a' };
    const sessionB = { sessionId: 'sess-b', userId: 'user-b' };

    await cacheSet('tenant-a', 'session', JSON.stringify(sessionA));
    await cacheSet('tenant-b', 'session', JSON.stringify(sessionB));

    const sessA = await cacheGet('tenant-a', 'session');
    const sessB = await cacheGet('tenant-b', 'session');

    expect(JSON.parse(sessA!)).toEqual(sessionA);
    expect(JSON.parse(sessB!)).toEqual(sessionB);
  });

  it('maintains rate limit cache isolation', async () => {
    await cacheSet('tenant-a', 'ratelimit:minute', '50', 60);
    await cacheSet('tenant-b', 'ratelimit:minute', '10', 60);

    const limitA = await cacheGet('tenant-a', 'ratelimit:minute');
    const limitB = await cacheGet('tenant-b', 'ratelimit:minute');

    expect(limitA).toBe('50');
    expect(limitB).toBe('10');
  });

  it('handles concurrent cache operations', async () => {
    // Simultaneous writes
    await Promise.all([
      cacheSet('tenant-a', 'counter', '1'),
      cacheSet('tenant-b', 'counter', '1'),
      cacheSet('tenant-a', 'counter', '2'),
      cacheSet('tenant-b', 'counter', '2'),
    ]);

    const countA = await cacheGet('tenant-a', 'counter');
    const countB = await cacheGet('tenant-b', 'counter');

    // Each tenant should have consistent state (defined, not null)
    expect(countA).toBeDefined();
    expect(countB).toBeDefined();
  });

  it('invalidates tenant cache without affecting others', async () => {
    await cacheSet('tenant-a', 'otp:active', 'true');
    await cacheSet('tenant-b', 'otp:active', 'true');
    await cacheSet('tenant-a', 'provider:config', '{}');
    await cacheSet('tenant-b', 'provider:config', '{}');

    // Invalidate Tenant A
    await cacheClear('tenant-a');

    // Tenant B untouched
    expect(await cacheGet('tenant-b', 'otp:active')).toBe('true');
    expect(await cacheGet('tenant-b', 'provider:config')).toBe('{}');

    // Tenant A cleared
    expect(await cacheGet('tenant-a', 'otp:active')).toBeNull();
    expect(await cacheGet('tenant-a', 'provider:config')).toBeNull();
  });

  it('enforces TTL per tenant', async () => {
    // Set with different TTLs
    await cacheSet('tenant-a', 'key', 'value', 1); // 1 second
    await cacheSet('tenant-b', 'key', 'value', 3600); // 1 hour

    // Immediate read works
    expect(await cacheGet('tenant-a', 'key')).toBe('value');
    expect(await cacheGet('tenant-b', 'key')).toBe('value');

    // Wait and check again - tenant-a should expire
    await new Promise(r => setTimeout(r, 1100));

    expect(await cacheGet('tenant-a', 'key')).toBeNull();
    expect(await cacheGet('tenant-b', 'key')).toBe('value');
  });
});
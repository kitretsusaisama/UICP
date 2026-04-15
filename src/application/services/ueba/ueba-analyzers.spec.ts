import { VelocityAnalyzer } from './velocity-analyzer';
import { GeoAnalyzer, GeoBaseline } from './geo-analyzer';
import { DeviceAnalyzer, DeviceSignals } from './device-analyzer';
import { CredentialStuffingAnalyzer } from './credential-stuffing-analyzer';
import { TorExitNodeChecker } from './tor-exit-node-checker';
import { ICachePort } from '../../ports/driven/i-cache.port';
import { IQueuePort } from '../../ports/driven/i-queue.port';
import { MaxmindGeoAdapter, GeoLocation } from '../../../infrastructure/geo/maxmind-geo.adapter';

/**
 * Unit tests for all five UEBA analyzers.
 * Implements: Req 11.2–11.7
 */

// ── Helpers ────────────────────────────────────────────────────────────────

function makeCache(overrides: Partial<ICachePort> = {}): ICachePort {
  return {
    get: jest.fn(async () => null),
    set: jest.fn(async () => {}),
    del: jest.fn(async () => {}),
    getdel: jest.fn(async () => null),
    sismember: jest.fn(async () => false),
    sadd: jest.fn(async () => 0),
    srem: jest.fn(async () => 0),
    smembers: jest.fn(async () => []),
    incr: jest.fn(async () => 1),
    expire: jest.fn(async () => true),
    ...overrides,
  };
}

function makeQueue(): IQueuePort {
  return {
    enqueue: jest.fn(async () => {}),
    enqueueRepeatable: jest.fn(async () => {}),
  };
}

function makeGeoAdapter(location: GeoLocation | null = null): MaxmindGeoAdapter {
  return {
    lookup: jest.fn(async () => location),
  } as unknown as MaxmindGeoAdapter;
}

// ── VelocityAnalyzer ───────────────────────────────────────────────────────

describe('VelocityAnalyzer — Req 11.2', () => {
  const USER_ID = 'user-001';
  const IP_HASH = 'abc123';

  it('returns 0.0 when all counters are at 0 (peek with no data)', async () => {
    const cache = makeCache({ get: jest.fn(async () => null) });
    const analyzer = new VelocityAnalyzer(cache);
    const score = await analyzer.peek(USER_ID, IP_HASH);
    expect(score).toBe(0.0);
  });

  it('score increases as request count increases (score method increments counters)', async () => {
    let counter = 0;
    const cache = makeCache({
      incr: jest.fn(async () => ++counter),
      expire: jest.fn(async () => true),
    });
    const analyzer = new VelocityAnalyzer(cache);

    const score1 = await analyzer.score(USER_ID, IP_HASH);
    expect(score1).toBeGreaterThan(0.0);
  });

  it('score is higher with more requests (monotone increase)', async () => {
    // Simulate low count (1 per window)
    const lowCache = makeCache({
      incr: jest.fn(async () => 1),
      expire: jest.fn(async () => true),
    });
    const lowAnalyzer = new VelocityAnalyzer(lowCache);
    const lowScore = await lowAnalyzer.score(USER_ID, IP_HASH);

    // Simulate high count (threshold reached per window)
    const highCache = makeCache({
      incr: jest.fn(async () => 30),
      expire: jest.fn(async () => true),
    });
    const highAnalyzer = new VelocityAnalyzer(highCache);
    const highScore = await highAnalyzer.score(USER_ID, IP_HASH);

    expect(highScore).toBeGreaterThan(lowScore);
  });

  it('score caps at 1.0 even when counters far exceed thresholds', async () => {
    const cache = makeCache({
      incr: jest.fn(async () => 9999),
      expire: jest.fn(async () => true),
    });
    const analyzer = new VelocityAnalyzer(cache);
    const score = await analyzer.score(USER_ID, IP_HASH);
    expect(score).toBe(1.0);
  });

  it('score is exactly 1.0 when all four windows are at or above threshold', async () => {
    // W1 threshold=5, W2 threshold=15, W3 threshold=10, W4 threshold=30
    // Return values at or above each threshold
    let callCount = 0;
    const thresholds = [5, 15, 10, 30];
    const cache = makeCache({
      incr: jest.fn(async () => thresholds[callCount++ % 4]!),
      expire: jest.fn(async () => true),
    });
    const analyzer = new VelocityAnalyzer(cache);
    const score = await analyzer.score(USER_ID, IP_HASH);
    expect(score).toBe(1.0);
  });

  it('peek() returns score based on current cache values without incrementing', async () => {
    const cache = makeCache({
      get: jest.fn(async () => '10'),
    });
    const analyzer = new VelocityAnalyzer(cache);
    const score = await analyzer.peek(USER_ID, IP_HASH);

    // incr should NOT be called
    expect(cache.incr).not.toHaveBeenCalled();
    expect(score).toBeGreaterThan(0.0);
    expect(score).toBeLessThanOrEqual(1.0);
  });

  it('score is always in [0.0, 1.0]', async () => {
    const cache = makeCache({
      incr: jest.fn(async () => 3),
      expire: jest.fn(async () => true),
    });
    const analyzer = new VelocityAnalyzer(cache);
    const score = await analyzer.score(USER_ID, IP_HASH);
    expect(score).toBeGreaterThanOrEqual(0.0);
    expect(score).toBeLessThanOrEqual(1.0);
  });

  it('returns 0.0 on cache failure (fail-safe)', async () => {
    const cache = makeCache({
      incr: jest.fn(async () => { throw new Error('Redis down'); }),
    });
    const analyzer = new VelocityAnalyzer(cache);
    const score = await analyzer.score(USER_ID, IP_HASH);
    expect(score).toBe(0.0);
  });
});

// ── GeoAnalyzer ────────────────────────────────────────────────────────────

describe('GeoAnalyzer — Req 11.3, Req 11.4', () => {
  const TENANT_ID = 'tenant-001';
  const USER_ID = 'user-001';
  const IP = '1.2.3.4';

  /** Build a baseline stored in cache at the expected key. */
  function makeBaselineCache(baseline: GeoBaseline): ICachePort {
    return makeCache({
      get: jest.fn(async (key: string) => {
        if (key === `geo-baseline:${TENANT_ID}:${USER_ID}`) {
          return JSON.stringify(baseline);
        }
        return null;
      }),
    });
  }

  /** A baseline set 1 hour ago at London coordinates. */
  function londonBaseline(hoursAgo = 1): GeoBaseline {
    const updatedAt = new Date(Date.now() - hoursAgo * 60 * 60 * 1000).toISOString();
    return { lat: 51.5074, lon: -0.1278, country: 'GB', city: 'London', updatedAt };
  }

  it('returns 0.1 when no baseline exists (first login)', async () => {
    const cache = makeCache({ get: jest.fn(async () => null) });
    const geoAdapter = makeGeoAdapter({ lat: 51.5074, lon: -0.1278, country: 'GB', city: 'London' });
    const analyzer = new GeoAnalyzer(cache, geoAdapter);

    const score = await analyzer.score(IP, TENANT_ID, USER_ID);
    expect(score).toBe(0.1);
  });

  it('returns 0.0 when GeoIP lookup returns null (unavailable)', async () => {
    const cache = makeCache();
    const geoAdapter = makeGeoAdapter(null);
    const analyzer = new GeoAnalyzer(cache, geoAdapter);

    const score = await analyzer.score(IP, TENANT_ID, USER_ID);
    expect(score).toBe(0.0);
  });

  it('returns 0.0 for same location (same country and city)', async () => {
    const baseline = londonBaseline(1);
    const cache = makeBaselineCache(baseline);
    const geoAdapter = makeGeoAdapter({ lat: 51.5074, lon: -0.1278, country: 'GB', city: 'London' });
    const analyzer = new GeoAnalyzer(cache, geoAdapter);

    const score = await analyzer.score(IP, TENANT_ID, USER_ID);
    expect(score).toBe(0.0);
  });

  it('returns 0.2 for city change within same country', async () => {
    const baseline = londonBaseline(1);
    const cache = makeBaselineCache(baseline);
    // Manchester is in GB but different city
    const geoAdapter = makeGeoAdapter({ lat: 53.4808, lon: -2.2426, country: 'GB', city: 'Manchester' });
    const analyzer = new GeoAnalyzer(cache, geoAdapter);

    const score = await analyzer.score(IP, TENANT_ID, USER_ID);
    expect(score).toBe(0.2);
  });

  it('returns 0.6 for country change', async () => {
    const baseline = londonBaseline(2);
    const cache = makeBaselineCache(baseline);
    // Paris, France — different country
    const geoAdapter = makeGeoAdapter({ lat: 48.8566, lon: 2.3522, country: 'FR', city: 'Paris' });
    const analyzer = new GeoAnalyzer(cache, geoAdapter);

    const score = await analyzer.score(IP, TENANT_ID, USER_ID);
    expect(score).toBe(0.6);
  });

  it('returns 1.0 for impossible travel (speed > 900 km/h)', async () => {
    // London to New York (~5570 km) in 1 hour = ~5570 km/h >> 900 km/h
    const baseline = londonBaseline(1);
    const cache = makeBaselineCache(baseline);
    const geoAdapter = makeGeoAdapter({ lat: 40.7128, lon: -74.006, country: 'US', city: 'New York' });
    const analyzer = new GeoAnalyzer(cache, geoAdapter);

    const score = await analyzer.score(IP, TENANT_ID, USER_ID);
    expect(score).toBe(1.0);
  });

  it('flags impossible travel even for very recent baselines (tiny time delta → huge speed)', async () => {
    // When updatedAt is just milliseconds ago, timeDeltaHours is tiny but > 0.
    // London to New York (~5570 km) / tiny hours = enormous speed → impossible travel → 1.0
    const baseline: GeoBaseline = {
      lat: 51.5074, lon: -0.1278, country: 'GB', city: 'London',
      updatedAt: new Date(Date.now() - 10).toISOString(), // 10ms ago
    };
    const cache = makeBaselineCache(baseline);
    const geoAdapter = makeGeoAdapter({ lat: 40.7128, lon: -74.006, country: 'US', city: 'New York' });
    const analyzer = new GeoAnalyzer(cache, geoAdapter);

    const score = await analyzer.score(IP, TENANT_ID, USER_ID);
    expect(score).toBe(1.0);
  });

  it('returns 0.1 when baseline JSON is malformed', async () => {
    const cache = makeCache({
      get: jest.fn(async () => 'not-valid-json{{{'),
    });
    const geoAdapter = makeGeoAdapter({ lat: 51.5074, lon: -0.1278, country: 'GB', city: 'London' });
    const analyzer = new GeoAnalyzer(cache, geoAdapter);

    const score = await analyzer.score(IP, TENANT_ID, USER_ID);
    expect(score).toBe(0.1);
  });

  it('updateBaseline() stores the location in cache with 30-day TTL', async () => {
    const cache = makeCache();
    const location: GeoLocation = { lat: 51.5074, lon: -0.1278, country: 'GB', city: 'London' };
    const geoAdapter = makeGeoAdapter(location);
    const analyzer = new GeoAnalyzer(cache, geoAdapter);

    await analyzer.updateBaseline(IP, TENANT_ID, USER_ID);

    expect(cache.set).toHaveBeenCalledWith(
      `geo-baseline:${TENANT_ID}:${USER_ID}`,
      expect.stringContaining('"country":"GB"'),
      30 * 24 * 60 * 60,
    );
  });

  it('updateBaseline() does nothing when GeoIP returns null', async () => {
    const cache = makeCache();
    const geoAdapter = makeGeoAdapter(null);
    const analyzer = new GeoAnalyzer(cache, geoAdapter);

    await analyzer.updateBaseline(IP, TENANT_ID, USER_ID);

    expect(cache.set).not.toHaveBeenCalled();
  });
});

// ── DeviceAnalyzer ─────────────────────────────────────────────────────────

describe('DeviceAnalyzer — Req 11.5', () => {
  const TENANT_ID = 'tenant-001';
  const USER_ID = 'user-001';

  const signals: DeviceSignals = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    acceptLanguage: 'en-US',
    screenResolution: '1920x1080',
    timezone: 'America/New_York',
    platform: 'Win32',
  };

  it('returns 0.0 for a known device (fingerprint in the set)', async () => {
    const analyzer = new DeviceAnalyzer(makeCache());
    const fingerprint = analyzer.computeFingerprint(signals);

    const cache = makeCache({
      sismember: jest.fn(async () => true),
      smembers: jest.fn(async () => [fingerprint]),
    });
    const analyzerWithCache = new DeviceAnalyzer(cache);

    const result = await analyzerWithCache.score(signals, TENANT_ID, USER_ID);
    expect(result.score).toBe(0.0);
    expect(result.fingerprint).toBe(fingerprint);
  });

  it('returns 0.5 for unknown device when user has existing devices', async () => {
    const cache = makeCache({
      sismember: jest.fn(async () => false),
      smembers: jest.fn(async () => ['some-other-fingerprint']),
    });
    const analyzer = new DeviceAnalyzer(cache);

    const result = await analyzer.score(signals, TENANT_ID, USER_ID);
    expect(result.score).toBe(0.5);
  });

  it('returns 0.1 for unknown device when user has no existing devices (new user)', async () => {
    const cache = makeCache({
      sismember: jest.fn(async () => false),
      smembers: jest.fn(async () => []),
    });
    const analyzer = new DeviceAnalyzer(cache);

    const result = await analyzer.score(signals, TENANT_ID, USER_ID);
    expect(result.score).toBe(0.1);
  });

  it('returns the computed fingerprint alongside the score', async () => {
    const cache = makeCache({
      sismember: jest.fn(async () => false),
      smembers: jest.fn(async () => []),
    });
    const analyzer = new DeviceAnalyzer(cache);
    const expectedFingerprint = analyzer.computeFingerprint(signals);

    const result = await analyzer.score(signals, TENANT_ID, USER_ID);
    expect(result.fingerprint).toBe(expectedFingerprint);
  });

  it('computeFingerprint() returns a 32-char hex string', () => {
    const analyzer = new DeviceAnalyzer(makeCache());
    const fp = analyzer.computeFingerprint(signals);
    expect(fp).toMatch(/^[0-9a-f]{32}$/);
  });

  it('computeFingerprint() is deterministic for the same signals', () => {
    const analyzer = new DeviceAnalyzer(makeCache());
    const fp1 = analyzer.computeFingerprint(signals);
    const fp2 = analyzer.computeFingerprint(signals);
    expect(fp1).toBe(fp2);
  });

  it('computeFingerprint() differs for different user agents', () => {
    const analyzer = new DeviceAnalyzer(makeCache());
    const fp1 = analyzer.computeFingerprint({ ...signals, userAgent: 'Chrome/100' });
    const fp2 = analyzer.computeFingerprint({ ...signals, userAgent: 'Firefox/99' });
    expect(fp1).not.toBe(fp2);
  });

  it('computeFingerprint() handles missing optional fields gracefully', () => {
    const analyzer = new DeviceAnalyzer(makeCache());
    const minimalSignals: DeviceSignals = { userAgent: 'Mozilla/5.0' };
    const fp = analyzer.computeFingerprint(minimalSignals);
    expect(fp).toMatch(/^[0-9a-f]{32}$/);
  });

  it('trustDevice() calls sadd with the correct key and fingerprint', async () => {
    const cache = makeCache();
    const analyzer = new DeviceAnalyzer(cache);
    const fingerprint = 'abc123fingerprint';

    await analyzer.trustDevice(fingerprint, TENANT_ID, USER_ID);

    expect(cache.sadd).toHaveBeenCalledWith(
      `devices:${TENANT_ID}:${USER_ID}`,
      fingerprint,
    );
  });

  it('returns 0.0 on cache failure (fail-safe)', async () => {
    const cache = makeCache({
      sismember: jest.fn(async () => { throw new Error('Redis down'); }),
    });
    const analyzer = new DeviceAnalyzer(cache);

    const result = await analyzer.score(signals, TENANT_ID, USER_ID);
    expect(result.score).toBe(0.0);
  });
});

// ── CredentialStuffingAnalyzer ─────────────────────────────────────────────

describe('CredentialStuffingAnalyzer — Req 11.6', () => {
  const IP_HASH = 'ip-hash-001';
  const TENANT_ID = 'tenant-001';

  function makeAnalyzerWithCounts(globalCount: number, tenantCount: number): CredentialStuffingAnalyzer {
    const cache = makeCache({
      get: jest.fn(async (key: string) => {
        if (key.includes(':global:')) return String(globalCount);
        if (key.includes(`:${TENANT_ID}:`)) return String(tenantCount);
        return null;
      }),
    });
    return new CredentialStuffingAnalyzer(cache);
  }

  describe('score() — read-only scoring', () => {
    it('returns 1.0 when global failures > 30', async () => {
      const analyzer = makeAnalyzerWithCounts(31, 0);
      const score = await analyzer.score(IP_HASH, TENANT_ID);
      expect(score).toBe(1.0);
    });

    it('returns 1.0 when global failures are exactly 31', async () => {
      const analyzer = makeAnalyzerWithCounts(31, 0);
      const score = await analyzer.score(IP_HASH, TENANT_ID);
      expect(score).toBe(1.0);
    });

    it('returns 0.7 when global failures > 15 but ≤ 30', async () => {
      const analyzer = makeAnalyzerWithCounts(16, 0);
      const score = await analyzer.score(IP_HASH, TENANT_ID);
      expect(score).toBe(0.7);
    });

    it('returns 0.5 when tenant failures > 10 (global ≤ 15)', async () => {
      const analyzer = makeAnalyzerWithCounts(5, 11);
      const score = await analyzer.score(IP_HASH, TENANT_ID);
      expect(score).toBe(0.5);
    });

    it('returns min(0.3, global/30) when no threshold exceeded', async () => {
      const analyzer = makeAnalyzerWithCounts(15, 0);
      const score = await analyzer.score(IP_HASH, TENANT_ID);
      expect(score).toBe(0.3); // min(0.3, 15/30) = min(0.3, 0.5) = 0.3
    });

    it('returns 0.0 when no failures recorded', async () => {
      const cache = makeCache({ get: jest.fn(async () => null) });
      const analyzer = new CredentialStuffingAnalyzer(cache);
      const score = await analyzer.score(IP_HASH, TENANT_ID);
      expect(score).toBe(0.0);
    });

    it('returns 0.0 on cache failure (fail-safe)', async () => {
      const cache = makeCache({
        get: jest.fn(async () => { throw new Error('Redis down'); }),
      });
      const analyzer = new CredentialStuffingAnalyzer(cache);
      const score = await analyzer.score(IP_HASH, TENANT_ID);
      expect(score).toBe(0.0);
    });
  });

  describe('recordFailure() — increments counters and returns updated score', () => {
    it('returns 1.0 when global failures exceed 30 after increment', async () => {
      let globalCount = 30;
      let tenantCount = 0;
      const cache = makeCache({
        incr: jest.fn(async (key: string) => {
          if (key.includes(':global:')) return ++globalCount;
          return ++tenantCount;
        }),
        expire: jest.fn(async () => true),
      });
      const analyzer = new CredentialStuffingAnalyzer(cache);
      const score = await analyzer.recordFailure(IP_HASH, TENANT_ID);
      expect(score).toBe(1.0);
    });

    it('sets TTL on first increment (count === 1)', async () => {
      const cache = makeCache({
        incr: jest.fn(async () => 1),
        expire: jest.fn(async () => true),
      });
      const analyzer = new CredentialStuffingAnalyzer(cache);
      await analyzer.recordFailure(IP_HASH, TENANT_ID);

      // expire should be called for both global and tenant keys (both return count=1)
      expect(cache.expire).toHaveBeenCalledTimes(2);
      expect(cache.expire).toHaveBeenCalledWith(expect.any(String), 600);
    });

    it('does NOT set TTL when count > 1 (window already started)', async () => {
      const cache = makeCache({
        incr: jest.fn(async () => 5),
        expire: jest.fn(async () => true),
      });
      const analyzer = new CredentialStuffingAnalyzer(cache);
      await analyzer.recordFailure(IP_HASH, TENANT_ID);

      expect(cache.expire).not.toHaveBeenCalled();
    });

    it('returns 0.0 on cache failure (fail-safe)', async () => {
      const cache = makeCache({
        incr: jest.fn(async () => { throw new Error('Redis down'); }),
      });
      const analyzer = new CredentialStuffingAnalyzer(cache);
      const score = await analyzer.recordFailure(IP_HASH, TENANT_ID);
      expect(score).toBe(0.0);
    });
  });
});

// ── TorExitNodeChecker ─────────────────────────────────────────────────────

describe('TorExitNodeChecker — Req 11.7', () => {
  const TOR_IP = '185.220.101.1';
  const CLEAN_IP = '8.8.8.8';

  it('returns 0.4 when IP is a known Tor exit node', async () => {
    const cache = makeCache({ sismember: jest.fn(async () => true) });
    const checker = new TorExitNodeChecker(cache, makeQueue());

    const score = await checker.score(TOR_IP);
    expect(score).toBe(0.4);
  });

  it('returns 0.0 when IP is not a Tor exit node', async () => {
    const cache = makeCache({ sismember: jest.fn(async () => false) });
    const checker = new TorExitNodeChecker(cache, makeQueue());

    const score = await checker.score(CLEAN_IP);
    expect(score).toBe(0.0);
  });

  it('checks the correct Redis key (tor-exit-nodes)', async () => {
    const cache = makeCache({ sismember: jest.fn(async () => false) });
    const checker = new TorExitNodeChecker(cache, makeQueue());

    await checker.score(TOR_IP);

    expect(cache.sismember).toHaveBeenCalledWith('tor-exit-nodes', TOR_IP);
  });

  it('returns 0.0 on cache failure (fail-open for availability)', async () => {
    const cache = makeCache({
      sismember: jest.fn(async () => { throw new Error('Redis down'); }),
    });
    const checker = new TorExitNodeChecker(cache, makeQueue());

    const score = await checker.score(TOR_IP);
    expect(score).toBe(0.0);
  });

  it('onModuleInit() registers the repeatable refresh job', async () => {
    const queue = makeQueue();
    const cache = makeCache();
    const checker = new TorExitNodeChecker(cache, queue);

    await checker.onModuleInit();

    expect(queue.enqueueRepeatable).toHaveBeenCalledWith(
      'tor-refresh',
      expect.objectContaining({ url: expect.stringContaining('torproject.org') }),
      expect.objectContaining({ cron: '0 */6 * * *', jobKey: 'tor-exit-nodes-refresh' }),
    );
  });

  describe('refreshList()', () => {
    it('deletes old set and populates with new IPs', async () => {
      const cache = makeCache();
      const checker = new TorExitNodeChecker(cache, makeQueue());
      const ips = ['1.2.3.4', '5.6.7.8', '9.10.11.12'];

      await checker.refreshList(ips);

      expect(cache.del).toHaveBeenCalledWith('tor-exit-nodes');
      expect(cache.sadd).toHaveBeenCalledWith('tor-exit-nodes', ...ips);
    });

    it('does nothing when the IP list is empty', async () => {
      const cache = makeCache();
      const checker = new TorExitNodeChecker(cache, makeQueue());

      await checker.refreshList([]);

      expect(cache.del).not.toHaveBeenCalled();
      expect(cache.sadd).not.toHaveBeenCalled();
    });

    it('batches large IP lists in chunks of 500', async () => {
      const cache = makeCache();
      const checker = new TorExitNodeChecker(cache, makeQueue());
      const ips = Array.from({ length: 1200 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256}`);

      await checker.refreshList(ips);

      // Should be called 3 times: 500 + 500 + 200
      expect(cache.sadd).toHaveBeenCalledTimes(3);
    });
  });
});

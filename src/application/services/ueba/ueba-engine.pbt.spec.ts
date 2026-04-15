import * as fc from 'fast-check';
import { UebaEngine, UebaContext } from './ueba-engine';
import { VelocityAnalyzer } from './velocity-analyzer';
import { GeoAnalyzer } from './geo-analyzer';
import { DeviceAnalyzer } from './device-analyzer';
import { CredentialStuffingAnalyzer } from './credential-stuffing-analyzer';
import { TorExitNodeChecker } from './tor-exit-node-checker';
import { ICachePort } from '../../ports/driven/i-cache.port';
import { IAlertRepository } from '../../ports/driven/i-alert.repository';
import { IMetricsPort } from '../../ports/driven/i-metrics.port';

/**
 * Property-Based Test — UEBA Composite Score Bounds (Property 12)
 *
 * **Property 12: UEBA composite score is always in [0.0, 1.0]**
 *
 * **Validates: Req 11.1, Req 11.8**
 *
 * For any combination of per-signal scores in [0.0, 1.0]:
 *   compositeScore = clamp(0.25·v + 0.30·g + 0.20·d + 0.15·cs + 0.10·tor, 0.0, 1.0)
 *
 * The property asserts that the composite score is always within [0.0, 1.0]
 * regardless of the individual signal values, across 10,000 runs.
 */

// ── Helpers ────────────────────────────────────────────────────────────────

/** Stub cache that does nothing — prevents side effects during scoring. */
function makeCache(): ICachePort {
  return {
    get: jest.fn(async () => null),
    set: jest.fn(async () => {}),
    del: jest.fn(async () => {}),
    getdel: jest.fn(async () => null),
    sismember: jest.fn(async () => false),
    sadd: jest.fn(async () => 0),
    srem: jest.fn(async () => 0),
    smembers: jest.fn(async () => []),
    incr: jest.fn(async () => 0),
    expire: jest.fn(async () => true),
  };
}

/** Stub alert repository — prevents DB writes during scoring. */
function makeAlertRepo(): IAlertRepository {
  return {
    save: jest.fn(async () => {}),
    findByTenantId: jest.fn(async () => ({ items: [], total: 0 })),
    updateWorkflow: jest.fn(async () => {}),
    findByUserId: jest.fn(async () => []),
  } as unknown as IAlertRepository;
}

/** Stub metrics — prevents metric emission side effects. */
function makeMetrics(): IMetricsPort {
  return {
    increment: jest.fn(),
    gauge: jest.fn(),
    histogram: jest.fn(),
    observe: jest.fn(),
  };
}

/**
 * Build a UebaEngine where each analyzer returns a fixed score.
 * All five analyzers are replaced with jest mocks returning the provided values.
 */
function makeEngine(signals: {
  velocity: number;
  geo: number;
  device: number;
  credentialStuffing: number;
  tor: number;
}): UebaEngine {
  const velocityAnalyzer = {
    score: jest.fn(async () => signals.velocity),
  } as unknown as VelocityAnalyzer;

  const geoAnalyzer = {
    score: jest.fn(async () => signals.geo),
  } as unknown as GeoAnalyzer;

  const deviceAnalyzer = {
    score: jest.fn(async () => ({ score: signals.device, fingerprint: 'fp-test' })),
  } as unknown as DeviceAnalyzer;

  const credentialStuffingAnalyzer = {
    score: jest.fn(async () => signals.credentialStuffing),
  } as unknown as CredentialStuffingAnalyzer;

  const torExitNodeChecker = {
    score: jest.fn(async () => signals.tor),
  } as unknown as TorExitNodeChecker;

  return new UebaEngine(
    velocityAnalyzer,
    geoAnalyzer,
    deviceAnalyzer,
    credentialStuffingAnalyzer,
    torExitNodeChecker,
    makeCache(),
    makeAlertRepo(),
    makeMetrics(),
  );
}

/** Minimal UebaContext for testing — no real IP or device data needed. */
const TEST_CTX: UebaContext = {
  ipHash: 'abc123',
  ip: '1.2.3.4',
  deviceSignals: { userAgent: 'Mozilla/5.0' },
  userId: 'user-001',
  tenantId: 'tenant-001',
};

// ── Arbitraries ────────────────────────────────────────────────────────────

/** Signal score in [0.0, 1.0] — matches the documented range for each analyzer. */
const signalArb = fc.float({ min: 0.0, max: 1.0, noNaN: true });

/** All five signal scores as a tuple. */
const allSignalsArb = fc.record({
  velocity: signalArb,
  geo: signalArb,
  device: signalArb,
  credentialStuffing: signalArb,
  tor: signalArb,
});

// ── Property Tests ─────────────────────────────────────────────────────────

describe('UebaEngine — Property 12: composite score bounds (Req 11.1, Req 11.8)', () => {
  it('composite score is always in [0.0, 1.0] for any combination of signal scores', async () => {
    /**
     * **Property 12: UEBA composite score is always in [0.0, 1.0]**
     * **Validates: Req 11.1, Req 11.8**
     *
     * Weighted formula (Section 10.2):
     *   rawScore = 0.25·velocity + 0.30·geo + 0.20·device + 0.15·credentialStuffing + 0.10·tor
     *   compositeScore = clamp(rawScore, 0.0, 1.0)
     *
     * Since all weights sum to 1.0 and each signal is in [0.0, 1.0],
     * the raw score is always in [0.0, 1.0] — but the clamp is still required
     * to guard against floating-point rounding errors.
     */
    await fc.assert(
      fc.asyncProperty(allSignalsArb, async (signals) => {
        const engine = makeEngine(signals);
        const result = await engine.evaluate(TEST_CTX);

        return result.score >= 0.0 && result.score <= 1.0;
      }),
      { numRuns: 10_000 },
    );
  });

  it('composite score is 0.0 when all signals are 0.0', async () => {
    const engine = makeEngine({ velocity: 0, geo: 0, device: 0, credentialStuffing: 0, tor: 0 });
    const result = await engine.evaluate(TEST_CTX);
    expect(result.score).toBe(0.0);
  });

  it('composite score is 1.0 when all signals are 1.0', async () => {
    const engine = makeEngine({ velocity: 1, geo: 1, device: 1, credentialStuffing: 1, tor: 1 });
    const result = await engine.evaluate(TEST_CTX);
    expect(result.score).toBe(1.0);
  });

  it('composite score matches the weighted formula for known inputs', async () => {
    /**
     * Manual verification of the weighted formula:
     *   0.25·0.8 + 0.30·0.6 + 0.20·0.4 + 0.15·0.2 + 0.10·0.4
     *   = 0.20 + 0.18 + 0.08 + 0.03 + 0.04 = 0.53
     */
    const engine = makeEngine({
      velocity: 0.8,
      geo: 0.6,
      device: 0.4,
      credentialStuffing: 0.2,
      tor: 0.4,
    });
    const result = await engine.evaluate(TEST_CTX);
    expect(result.score).toBeCloseTo(0.53, 5);
  });

  it('score is monotonically non-decreasing as any single signal increases', async () => {
    /**
     * Increasing any signal score should never decrease the composite score.
     * Validates the weighted sum is monotone in each component.
     */
    await fc.assert(
      fc.asyncProperty(
        allSignalsArb,
        fc.constantFrom('velocity', 'geo', 'device', 'credentialStuffing', 'tor') as fc.Arbitrary<'velocity' | 'geo' | 'device' | 'credentialStuffing' | 'tor'>,
        fc.float({ min: 0.0, max: 1.0, noNaN: true }),
        async (baseSignals, signalKey, higherValue) => {
          // Only test when the higher value is actually higher
          if (higherValue <= baseSignals[signalKey]) return true;

          const lowerEngine = makeEngine(baseSignals);
          const higherEngine = makeEngine({ ...baseSignals, [signalKey]: higherValue });

          const [lowerResult, higherResult] = await Promise.all([
            lowerEngine.evaluate(TEST_CTX),
            higherEngine.evaluate(TEST_CTX),
          ]);

          return higherResult.score >= lowerResult.score;
        },
      ),
      { numRuns: 2_000 },
    );
  });

  it('score is always a finite number (no NaN or Infinity)', async () => {
    await fc.assert(
      fc.asyncProperty(allSignalsArb, async (signals) => {
        const engine = makeEngine(signals);
        const result = await engine.evaluate(TEST_CTX);
        return Number.isFinite(result.score);
      }),
      { numRuns: 10_000 },
    );
  });
});

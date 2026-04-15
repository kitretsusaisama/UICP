import * as fc from 'fast-check';
import { AdaptiveBcrypt } from './adaptive-bcrypt';
import { ServerLoadMonitor } from './server-load-monitor';

/**
 * Property-based test for AdaptiveBcrypt.
 *
 * Property 13: getBcryptRounds() ≥ 10 under any load score
 *
 * Validates: Req 2.9 — bcrypt with adaptive Bcrypt_Rounds
 *
 * The MIN_ROUNDS floor of 10 must hold regardless of:
 *   - the composite load score reported by ServerLoadMonitor
 *   - the internally calibrated currentRounds value
 */

const MIN_ROUNDS = 10;
const MAX_ROUNDS = 13;

/**
 * Build an AdaptiveBcrypt instance with a mocked ServerLoadMonitor
 * that returns the given composite score.
 */
function makeAdaptiveBcrypt(loadScore: number, currentRounds = 12): AdaptiveBcrypt {
  const mockMonitor = {
    getCompositeScore: () => loadScore,
  } as unknown as ServerLoadMonitor;

  const instance = new AdaptiveBcrypt(mockMonitor);

  // Bypass onModuleInit (which runs calibration + timer) by directly
  // setting the internal currentRounds via the calibration path.
  // We cast to access the private field for test purposes.
  (instance as unknown as { currentRounds: number }).currentRounds = currentRounds;

  return instance;
}

describe('AdaptiveBcrypt — Property 13: bcrypt rounds floor', () => {
  /**
   * Property 13: getCurrentRounds() ≥ 10 for ALL load scores in [0.0, 1.0].
   *
   * This covers both branches of getCurrentRounds():
   *   - High load (score > 0.80) → returns MIN_ROUNDS (10)
   *   - Normal load             → returns currentRounds (clamped to [10, 13])
   */
  it('Property 13: getCurrentRounds() is always ≥ 10 regardless of load score', () => {
    fc.assert(
      fc.property(
        fc.float({ min: 0.0, max: 1.0, noNaN: true }),
        fc.integer({ min: MIN_ROUNDS, max: MAX_ROUNDS }),
        (loadScore, currentRounds) => {
          const svc = makeAdaptiveBcrypt(loadScore, currentRounds);
          const rounds = svc.getCurrentRounds();

          expect(rounds).toBeGreaterThanOrEqual(MIN_ROUNDS);
        },
      ),
      { numRuns: 1_000 },
    );
  });

  /**
   * Explicit high-load branch: when load score > 0.80, rounds must equal MIN_ROUNDS (10).
   */
  it('Property 13 (high-load branch): getCurrentRounds() = 10 when load score > 0.80', () => {
    fc.assert(
      fc.property(
        fc.float({ min: Math.fround(0.801), max: Math.fround(1.0), noNaN: true }),
        fc.integer({ min: MIN_ROUNDS, max: MAX_ROUNDS }),
        (loadScore, currentRounds) => {
          const svc = makeAdaptiveBcrypt(loadScore, currentRounds);
          expect(svc.getCurrentRounds()).toBe(MIN_ROUNDS);
        },
      ),
      { numRuns: 1_000 },
    );
  });

  /**
   * Explicit normal-load branch: when load score ≤ 0.80, rounds must equal currentRounds
   * and still be ≥ MIN_ROUNDS.
   */
  it('Property 13 (normal-load branch): getCurrentRounds() = currentRounds when load score ≤ 0.80', () => {
    fc.assert(
      fc.property(
        // Use max just below the HIGH_LOAD_THRESHOLD (0.80) to stay in the normal-load branch.
        // Math.fround(0.80) is the largest 32-bit float ≤ 0.80, so scores in this range
        // will not trigger the high-load path (which requires score > 0.80).
        fc.float({ min: Math.fround(0.0), max: Math.fround(0.7999999), noNaN: true }),
        fc.integer({ min: MIN_ROUNDS, max: MAX_ROUNDS }),
        (loadScore, currentRounds) => {
          const svc = makeAdaptiveBcrypt(loadScore, currentRounds);
          const rounds = svc.getCurrentRounds();

          expect(rounds).toBe(currentRounds);
          expect(rounds).toBeGreaterThanOrEqual(MIN_ROUNDS);
        },
      ),
      { numRuns: 1_000 },
    );
  });
});

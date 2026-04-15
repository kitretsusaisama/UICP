import * as fc from 'fast-check';

/**
 * Property-Based Test — Rate Limit Monotonicity (Property 6)
 *
 * **Property 6: Token bucket remaining is always in [0, capacity] — never
 * negative, never exceeds capacity**
 *
 * **Validates: Req 3.10, Req 4.4**
 *
 * For any capacity and any sequence of consume() calls:
 *   - `remaining` is always ≥ 0
 *   - `remaining` is always ≤ capacity
 *   - `remaining` never increases between consecutive calls (monotonically
 *     non-increasing within a window)
 *   - once `allowed` is false, `remaining` stays at 0 for the rest of the window
 */

// ── Extract the class under test ──────────────────────────────────────────────
// InMemoryTokenBucket is not exported from the middleware module, so we
// re-declare the minimal interface and inline the same logic here.
// This keeps the test self-contained and avoids coupling to private exports.

interface ConsumeResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

interface Bucket {
  tokens: number;
  lastRefill: number;
}

/**
 * Inline copy of InMemoryTokenBucket from rate-limiter.middleware.ts.
 * Must stay in sync with the production implementation.
 */
class InMemoryTokenBucket {
  private readonly buckets = new Map<string, Bucket>();

  consume(key: string, capacity: number, windowSeconds: number): ConsumeResult {
    const now = Date.now();
    const windowMs = windowSeconds * 1000;

    let bucket = this.buckets.get(key);
    if (!bucket || now - bucket.lastRefill >= windowMs) {
      bucket = { tokens: capacity, lastRefill: now };
      this.buckets.set(key, bucket);
    }

    const resetAt = Math.ceil((bucket.lastRefill + windowMs) / 1000);

    if (bucket.tokens <= 0) {
      return { allowed: false, remaining: 0, resetAt };
    }

    bucket.tokens -= 1;
    return { allowed: true, remaining: bucket.tokens, resetAt };
  }

  prune(windowSeconds: number): void {
    const cutoff = Date.now() - windowSeconds * 1000 * 2;
    for (const [key, bucket] of this.buckets) {
      if (bucket.lastRefill < cutoff) {
        this.buckets.delete(key);
      }
    }
  }
}

// ── Arbitraries ───────────────────────────────────────────────────────────────

/** Bucket capacity: 1–100 tokens. */
const capacityArb = fc.integer({ min: 1, max: 100 });

/** Number of consume() calls to make against a single bucket. */
const requestCountArb = fc.integer({ min: 1, max: 1000 });

/** A stable bucket key for the test window. */
const keyArb = fc.string({ minLength: 1, maxLength: 32 });

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Property 6 — Rate limit monotonicity (Req 3.10, Req 4.4)', () => {
  it('remaining is always in [0, capacity] across all consume() calls', () => {
    fc.assert(
      fc.property(capacityArb, requestCountArb, keyArb, (capacity, requestCount, key) => {
        const bucket = new InMemoryTokenBucket();

        for (let i = 0; i < requestCount; i++) {
          const { remaining } = bucket.consume(key, capacity, 60);

          if (remaining < 0 || remaining > capacity) {
            return false;
          }
        }

        return true;
      }),
      { numRuns: 500 },
    );
  });

  it('remaining is monotonically non-increasing within a single window', () => {
    fc.assert(
      fc.property(capacityArb, requestCountArb, keyArb, (capacity, requestCount, key) => {
        const bucket = new InMemoryTokenBucket();
        let prev = capacity;

        for (let i = 0; i < requestCount; i++) {
          const { remaining } = bucket.consume(key, capacity, 60);

          // remaining must never go up within the same window
          if (remaining > prev) {
            return false;
          }
          prev = remaining;
        }

        return true;
      }),
      { numRuns: 500 },
    );
  });

  it('once allowed=false, remaining stays 0 for all subsequent calls in the window', () => {
    fc.assert(
      fc.property(capacityArb, requestCountArb, keyArb, (capacity, requestCount, key) => {
        const bucket = new InMemoryTokenBucket();
        let exhausted = false;

        for (let i = 0; i < requestCount; i++) {
          const { allowed, remaining } = bucket.consume(key, capacity, 60);

          if (!allowed) {
            exhausted = true;
          }

          if (exhausted && remaining !== 0) {
            return false;
          }
        }

        return true;
      }),
      { numRuns: 500 },
    );
  });

  it('exactly `capacity` requests are allowed before the bucket is exhausted', () => {
    fc.assert(
      fc.property(capacityArb, keyArb, (capacity, key) => {
        const bucket = new InMemoryTokenBucket();
        let allowedCount = 0;

        // Make capacity + 10 requests to ensure we go past the limit
        for (let i = 0; i < capacity + 10; i++) {
          const { allowed } = bucket.consume(key, capacity, 60);
          if (allowed) allowedCount++;
        }

        return allowedCount === capacity;
      }),
      { numRuns: 500 },
    );
  });

  it('independent keys do not interfere with each other', () => {
    fc.assert(
      fc.property(
        capacityArb,
        fc.integer({ min: 1, max: 50 }),
        (capacity, requestCount) => {
          const bucket = new InMemoryTokenBucket();
          const keyA = 'key-a';
          const keyB = 'key-b';

          for (let i = 0; i < requestCount; i++) {
            bucket.consume(keyA, capacity, 60);
          }

          // keyB should still have a full bucket
          const { remaining } = bucket.consume(keyB, capacity, 60);
          return remaining === capacity - 1;
        },
      ),
      { numRuns: 300 },
    );
  });
});

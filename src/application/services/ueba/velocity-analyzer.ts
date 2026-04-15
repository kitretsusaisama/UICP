import { Injectable, Logger } from '@nestjs/common';
import { ICachePort } from '../../ports/driven/i-cache.port';

/**
 * Measures login attempt frequency across four sliding windows using Redis INCR + EXPIRE.
 *
 * Windows and thresholds (Section 10.1):
 *   W₁ = user:{userId}:1m   threshold 5
 *   W₂ = user:{userId}:5m   threshold 15
 *   W₃ = ip:{ipHash}:1m     threshold 10
 *   W₄ = ip:{ipHash}:10m    threshold 30
 *
 * Per-window score: s(W, T) = min(1.0, count(W) / T)
 * Composite:        velocity_score = 0.25·s₁ + 0.25·s₂ + 0.25·s₃ + 0.25·s₄
 *
 * Implements: Req 11.2
 */
@Injectable()
export class VelocityAnalyzer {
  private readonly logger = new Logger(VelocityAnalyzer.name);

  // Window TTLs in seconds
  private static readonly WINDOWS = [
    { keyFn: (userId: string) => `vel:user:${userId}:1m`,  ttl: 60,   threshold: 5  },
    { keyFn: (userId: string) => `vel:user:${userId}:5m`,  ttl: 300,  threshold: 15 },
    { keyFn: (ipHash: string) => `vel:ip:${ipHash}:1m`,    ttl: 60,   threshold: 10 },
    { keyFn: (ipHash: string) => `vel:ip:${ipHash}:10m`,   ttl: 600,  threshold: 30 },
  ] as const;

  constructor(private readonly cache: ICachePort) {}

  /**
   * Increments all four sliding window counters and returns the composite velocity score.
   * Each window key has TTL = window_duration; Redis TTL handles natural decay.
   */
  async score(userId: string, ipHash: string): Promise<number> {
    const keys = [
      { key: `vel:user:${userId}:1m`,  ttl: 60,   threshold: 5  },
      { key: `vel:user:${userId}:5m`,  ttl: 300,  threshold: 15 },
      { key: `vel:ip:${ipHash}:1m`,    ttl: 60,   threshold: 10 },
      { key: `vel:ip:${ipHash}:10m`,   ttl: 600,  threshold: 30 },
    ];

    const results = await Promise.allSettled(
      keys.map(async ({ key, ttl }) => {
        const count = await this.cache.incr(key);
        // Set TTL only on first increment (count === 1) to avoid resetting the window
        if (count === 1) {
          await this.cache.expire(key, ttl);
        }
        return count;
      }),
    );

    let composite = 0;
    for (let i = 0; i < results.length; i++) {
      const result = results[i]!;
      const threshold = keys[i]!.threshold;
      if (result.status === 'fulfilled') {
        composite += 0.25 * Math.min(1.0, result.value / threshold);
      } else {
        this.logger.warn({ key: keys[i]!.key, err: result.reason }, 'VelocityAnalyzer window failed — using 0.0');
      }
    }

    return Math.min(1.0, Math.max(0.0, composite));
  }

  /**
   * Returns the current velocity score without incrementing counters.
   * Used for read-only scoring (e.g. re-evaluation without a new attempt).
   */
  async peek(userId: string, ipHash: string): Promise<number> {
    const keys = [
      { key: `vel:user:${userId}:1m`,  threshold: 5  },
      { key: `vel:user:${userId}:5m`,  threshold: 15 },
      { key: `vel:ip:${ipHash}:1m`,    threshold: 10 },
      { key: `vel:ip:${ipHash}:10m`,   threshold: 30 },
    ];

    const results = await Promise.allSettled(
      keys.map(({ key }) => this.cache.get(key)),
    );

    let composite = 0;
    for (let i = 0; i < results.length; i++) {
      const result = results[i]!;
      const threshold = keys[i]!.threshold;
      if (result.status === 'fulfilled' && result.value !== null) {
        const count = parseInt(result.value, 10);
        composite += 0.25 * Math.min(1.0, count / threshold);
      }
    }

    return Math.min(1.0, Math.max(0.0, composite));
  }
}

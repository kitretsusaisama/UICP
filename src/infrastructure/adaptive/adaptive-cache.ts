import { Injectable, Logger } from '@nestjs/common';

/**
 * TTL multiplier table — Section 12.3.
 * Maps hit rate ranges to TTL multipliers.
 */
const TTL_MULTIPLIER_TABLE: ReadonlyArray<{
  hitRateMin: number;
  hitRateMax: number;
  multiplier: number;
}> = [
  { hitRateMin: 0.90, hitRateMax: 1.01, multiplier: 1.5 }, // hot data → extend TTL
  { hitRateMin: 0.70, hitRateMax: 0.90, multiplier: 1.2 }, // warm data → slight extension
  { hitRateMin: 0.50, hitRateMax: 0.70, multiplier: 1.0 }, // neutral
  { hitRateMin: 0.00, hitRateMax: 0.50, multiplier: 0.7 }, // cold data → reduce TTL
];

/** Sliding window of last N operations per key type. */
class HitRateTracker {
  private readonly windowSize: number;
  /** Circular buffer: true = hit, false = miss */
  private readonly windows = new Map<string, boolean[]>();
  private readonly cursors = new Map<string, number>();
  private readonly counts = new Map<string, number>();

  constructor(windowSize = 1000) {
    this.windowSize = windowSize;
  }

  record(keyType: string, isHit: boolean): void {
    if (!this.windows.has(keyType)) {
      this.windows.set(keyType, new Array<boolean>(this.windowSize).fill(false));
      this.cursors.set(keyType, 0);
      this.counts.set(keyType, 0);
    }

    const buf = this.windows.get(keyType)!;
    const cursor = this.cursors.get(keyType)!;
    const count = this.counts.get(keyType)!;

    // Overwrite oldest entry
    buf[cursor] = isHit;
    this.cursors.set(keyType, (cursor + 1) % this.windowSize);
    this.counts.set(keyType, Math.min(count + 1, this.windowSize));
  }

  getHitRate(keyType: string): number {
    const buf = this.windows.get(keyType);
    const count = this.counts.get(keyType) ?? 0;
    if (!buf || count === 0) return 0.5; // default neutral rate

    let hits = 0;
    for (let i = 0; i < count; i++) {
      if (buf[i]) hits++;
    }
    return hits / count;
  }
}

/**
 * Adaptive cache TTL service — Section 12.3.
 *
 * Tracks per-key-type hit rates in a sliding window of the last 1000 operations.
 * Applies a TTL multiplier from the table and adds ±10% jitter to prevent
 * thundering herd / cache stampede.
 *
 * Usage: inject into RedisCacheAdapter and call `getAdaptiveTtl` before `set`.
 */
@Injectable()
export class AdaptiveCacheService {
  private readonly logger = new Logger(AdaptiveCacheService.name);
  private readonly tracker = new HitRateTracker(1000);

  /**
   * Record a cache operation result for the given key type.
   * Call this after every get() to keep hit-rate statistics current.
   */
  recordAccess(keyType: string, isHit: boolean): void {
    this.tracker.record(keyType, isHit);
  }

  /**
   * Compute an adaptive TTL for the given base TTL and key type.
   * Applies the multiplier from TTL_MULTIPLIER_TABLE and ±10% jitter.
   *
   * @param baseTtlSeconds  The nominal TTL configured for this key type.
   * @param keyType         Logical key category (e.g. 'session', 'token', 'abac').
   * @returns               Adjusted TTL in whole seconds (minimum 1).
   */
  getAdaptiveTtl(baseTtlSeconds: number, keyType: string): number {
    const hitRate = this.tracker.getHitRate(keyType);
    const row = TTL_MULTIPLIER_TABLE.find(
      (r) => hitRate >= r.hitRateMin && hitRate < r.hitRateMax,
    );
    const multiplier = row?.multiplier ?? 1.0;

    // Jitter ±10% to prevent thundering herd
    const jitter = 1.0 + (Math.random() * 0.2 - 0.1);
    const ttl = Math.round(baseTtlSeconds * multiplier * jitter);

    this.logger.debug(
      { keyType, hitRate, multiplier, jitter, baseTtlSeconds, ttl },
      'Adaptive TTL computed',
    );

    return Math.max(1, ttl);
  }

  /** Expose current hit rate for a key type (useful for metrics/logging). */
  getHitRate(keyType: string): number {
    return this.tracker.getHitRate(keyType);
  }
}

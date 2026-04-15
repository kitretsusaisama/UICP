import { Injectable, Logger } from '@nestjs/common';

/**
 * Token bucket entry for a single rate limit key.
 */
interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

/**
 * In-memory token bucket rate limiter (Req 15.2 fallback).
 *
 * Used when the Redis circuit breaker is OPEN and distributed rate limiting
 * is unavailable. Each pod maintains its own per-key token bucket.
 *
 * Limitations vs Redis rate limiter:
 * - Per-pod only — not distributed across pods
 * - State is lost on pod restart
 * - Conservative: each pod enforces the full limit independently
 *   (effective limit = configured limit / pod count)
 *
 * This is intentionally conservative to prevent abuse during Redis outages.
 */
@Injectable()
export class InMemoryRateLimiter {
  private readonly logger = new Logger(InMemoryRateLimiter.name);

  /** Map of key → token bucket state. */
  private readonly buckets = new Map<string, TokenBucket>();

  /** Cleanup interval — remove stale buckets every 5 minutes. */
  private readonly cleanupIntervalMs = 5 * 60 * 1000;
  private lastCleanup = Date.now();

  /**
   * Attempt to consume `cost` tokens from the bucket for `key`.
   *
   * @param key         Rate limit key (e.g., `ratelimit:tenant:ip`)
   * @param limit       Maximum tokens per window
   * @param windowMs    Window size in milliseconds
   * @param cost        Tokens to consume (default: 1)
   * @returns true if allowed, false if rate limited
   */
  consume(key: string, limit: number, windowMs: number, cost = 1): boolean {
    this.maybeCleanup();

    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket) {
      bucket = { tokens: limit, lastRefill: now };
      this.buckets.set(key, bucket);
    }

    // Refill tokens based on elapsed time (token bucket algorithm)
    const elapsed = now - bucket.lastRefill;
    if (elapsed >= windowMs) {
      // Full window elapsed — reset to full
      bucket.tokens = limit;
      bucket.lastRefill = now;
    } else {
      // Partial refill proportional to elapsed time
      const refill = Math.floor((elapsed / windowMs) * limit);
      if (refill > 0) {
        bucket.tokens = Math.min(limit, bucket.tokens + refill);
        bucket.lastRefill = now;
      }
    }

    if (bucket.tokens < cost) {
      this.logger.debug({ key, remaining: bucket.tokens }, 'In-memory rate limit exceeded');
      return false;
    }

    bucket.tokens -= cost;
    return true;
  }

  /**
   * Returns the number of remaining tokens for a key.
   */
  getRemaining(key: string, limit: number): number {
    const bucket = this.buckets.get(key);
    return bucket ? bucket.tokens : limit;
  }

  /**
   * Reset the token bucket for a key (e.g., after Redis recovers).
   */
  reset(key: string): void {
    this.buckets.delete(key);
  }

  /**
   * Clear all buckets (e.g., after Redis circuit closes — conservative reset to 0).
   * Per Section 11.6: in-memory rate limit state discarded on recovery.
   */
  clearAll(): void {
    this.buckets.clear();
    this.logger.log('In-memory rate limiter state cleared (Redis recovered)');
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private maybeCleanup(): void {
    const now = Date.now();
    if (now - this.lastCleanup < this.cleanupIntervalMs) return;

    this.lastCleanup = now;
    // Remove buckets that haven't been accessed in 2x the cleanup interval
    const staleThreshold = now - this.cleanupIntervalMs * 2;
    for (const [key, bucket] of this.buckets.entries()) {
      if (bucket.lastRefill < staleThreshold) {
        this.buckets.delete(key);
      }
    }
  }
}

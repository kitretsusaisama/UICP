import { Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional, Inject } from '@nestjs/common';
import { ICachePort } from '../../application/ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';

/** Rolling error-rate window entry. */
interface ErrorRateWindow {
  total: number;
  errors: number;
  windowStart: number; // epoch seconds
}

/**
 * Adaptive rate limit service — Section 12.6.
 *
 * Tracks 5xx error rate over a rolling 60-second window and adjusts a
 * per-tenant rate limit multiplier stored in Redis.
 *
 * Algorithm:
 * - errorRate > 10%  → multiply by 0.7  (tighten, floor 0.3)
 * - errorRate < 1%   → multiply by 1.05 (restore, cap 1.0)
 * - 1–10%            → no change
 *
 * Cycle: every 30 seconds.
 * Redis key: `rate-limit-multiplier:{tenantId}` with TTL 60s.
 */
@Injectable()
export class AdaptiveRateLimitService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AdaptiveRateLimitService.name);

  /** In-memory error rate windows per tenant. */
  private readonly windows = new Map<string, ErrorRateWindow>();

  /** Current multiplier per tenant (in-memory mirror of Redis). */
  private readonly multipliers = new Map<string, number>();

  private timer: NodeJS.Timeout | null = null;

  constructor(
    @Optional() @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache?: ICachePort,
  ) {}

  onModuleInit(): void {
    this.timer = setInterval(() => void this.runCycle(), 30_000);
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /**
   * Record an HTTP response for a tenant.
   * Call this from the global exception filter or response interceptor.
   *
   * @param tenantId   Tenant identifier.
   * @param statusCode HTTP response status code.
   */
  recordResponse(tenantId: string, statusCode: number): void {
    const nowSec = Math.floor(Date.now() / 1000);
    const windowDuration = 60;

    let win = this.windows.get(tenantId);
    if (!win || nowSec - win.windowStart >= windowDuration) {
      win = { total: 0, errors: 0, windowStart: nowSec };
      this.windows.set(tenantId, win);
    }

    win.total++;
    if (statusCode >= 500) {
      win.errors++;
    }
  }

  /**
   * Get the current rate limit multiplier for a tenant.
   * Returns 1.0 when no data is available.
   */
  getMultiplier(tenantId: string): number {
    return this.multipliers.get(tenantId) ?? 1.0;
  }

  /**
   * Run one adaptation cycle across all tracked tenants.
   * Exposed for testing.
   */
  async runCycle(): Promise<void> {
    for (const [tenantId, win] of this.windows) {
      if (win.total === 0) continue;

      const errorRate = win.errors / win.total;
      const current = this.multipliers.get(tenantId) ?? 1.0;
      const next = this.adaptMultiplier(current, errorRate);

      if (next !== current) {
        this.multipliers.set(tenantId, next);
        this.logger.log(
          { tenantId, errorRate, oldMultiplier: current, newMultiplier: next },
          'Rate limit multiplier adjusted',
        );
      }

      // Persist to Redis so RateLimiterMiddleware can read it (Section 12.6)
      if (this.cache) {
        try {
          await this.cache.set(
            `rate-limit-multiplier:${tenantId}`,
            String(next),
            60, // TTL 60s — refreshed every 30s cycle
          );
        } catch (err) {
          this.logger.warn({ err, tenantId }, 'Failed to persist rate limit multiplier to Redis');
        }
      }
    }
  }

  // ── Private ──────────────────────────────────────────────────────────────

  private adaptMultiplier(current: number, errorRate: number): number {
    if (errorRate > 0.10) {
      // >10% error rate → tighten limits
      return Math.max(0.3, current * 0.7);
    } else if (errorRate < 0.01) {
      // <1% error rate → gradually restore
      return Math.min(1.0, current * 1.05);
    }
    return current; // 1–10% → no change
  }
}

import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';

/** Pool metrics snapshot used for adaptive decisions. */
export interface PoolMetrics {
  waiting: number;
  idle: number;
  total: number;
}

/** Minimal interface for a pool that supports dynamic sizing. */
export interface AdaptablePool {
  getWaitingCount(): number;
  getIdleCount(): number;
  getTotalCount(): number;
  /** Increase the connection limit by `count`. */
  expand(count: number): Promise<void>;
  /** Decrease the connection limit by `count`, releasing idle connections. */
  shrink(count: number): Promise<void>;
}

const POOL_CONFIG = {
  min: 5,
  max: 20,
} as const;

/**
 * Adaptive DB pool manager — Section 12.4.
 *
 * Monitors pool metrics every 10 seconds and adjusts pool size:
 * - Expands by 2 when `waiting > 5` (up to max=20).
 * - Shrinks by 1 when `idle > 2×min` (down to min=5).
 *
 * Attach a pool via `attach()` after the pool is created.
 */
@Injectable()
export class AdaptiveDbPoolService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AdaptiveDbPoolService.name);
  private pool: AdaptablePool | null = null;
  private timer: NodeJS.Timeout | null = null;

  onModuleInit(): void {
    this.timer = setInterval(() => void this.adaptDbPool(), 10_000);
    // Allow the process to exit even if this timer is still running
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /** Register the pool to be managed. Call this once the pool is ready. */
  attach(pool: AdaptablePool): void {
    this.pool = pool;
  }

  /** Detach the managed pool (e.g. on shutdown). */
  detach(): void {
    this.pool = null;
  }

  /** Snapshot current pool metrics (returns zeros when no pool attached). */
  getMetrics(): PoolMetrics {
    if (!this.pool) return { waiting: 0, idle: 0, total: 0 };
    return {
      waiting: this.pool.getWaitingCount(),
      idle: this.pool.getIdleCount(),
      total: this.pool.getTotalCount(),
    };
  }

  /** Run one adaptation cycle. Exposed for testing. */
  async adaptDbPool(): Promise<void> {
    if (!this.pool) return;

    const waiting = this.pool.getWaitingCount();
    const idle = this.pool.getIdleCount();
    const current = this.pool.getTotalCount();

    if (waiting > 5 && current < POOL_CONFIG.max) {
      await this.pool.expand(2);
      this.logger.log(
        { waiting, current, newSize: current + 2, action: 'pool_expanded' },
        'DB pool expanded',
      );
    } else if (idle > 2 * POOL_CONFIG.min && current > POOL_CONFIG.min) {
      await this.pool.shrink(1);
      this.logger.log(
        { idle, current, newSize: current - 1, action: 'pool_shrunk' },
        'DB pool shrunk',
      );
    }
  }
}

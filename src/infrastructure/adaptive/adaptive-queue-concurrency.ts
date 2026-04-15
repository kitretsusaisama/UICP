import { Injectable, Logger } from '@nestjs/common';

/** Base concurrency limits per queue — Section 11.2. */
const QUEUE_CONCURRENCY: Readonly<Record<string, number>> = {
  'otp-send': 5,
  'audit-write': 20,
  'soc-alert': 3,
  'outbox-relay': 10,
  'email-welcome': 5,
};

/** Minimal interface for reading composite server load score. */
export interface LoadScoreProvider {
  getCompositeScore(): number; // [0.0, 1.0]
}

/** Minimal interface for reading current queue depth. */
export interface QueueDepthProvider {
  getDepth(queue: string): number;
}

/**
 * Adaptive queue concurrency service — Section 12.5.
 *
 * Computes per-queue concurrency based on:
 * - Composite server load score (CPU + memory + event-loop lag).
 * - Current queue depth.
 *
 * Result is bounded to [1, 2×base].
 *
 * Usage: call `getAdaptiveConcurrency(queue)` from BullMQ worker setup
 * and re-apply on each tuning cycle.
 */
@Injectable()
export class AdaptiveQueueConcurrencyService {
  private readonly logger = new Logger(AdaptiveQueueConcurrencyService.name);

  private loadProvider: LoadScoreProvider | null = null;
  private depthProvider: QueueDepthProvider | null = null;

  /** Register the load score provider (e.g. ServerLoadMonitor). */
  setLoadProvider(provider: LoadScoreProvider): void {
    this.loadProvider = provider;
  }

  /** Register the queue depth provider (e.g. BullMQ queue wrapper). */
  setDepthProvider(provider: QueueDepthProvider): void {
    this.depthProvider = provider;
  }

  /**
   * Compute adaptive concurrency for the given queue.
   *
   * @param queue  Queue name matching keys in QUEUE_CONCURRENCY.
   * @returns      Adjusted concurrency value, bounded to [1, 2×base].
   */
  getAdaptiveConcurrency(queue: string): number {
    const base = QUEUE_CONCURRENCY[queue] ?? 5;
    const loadScore = this.loadProvider?.getCompositeScore() ?? 0;
    const depth = this.depthProvider?.getDepth(queue) ?? 0;

    // Load factor: reduce concurrency under high load
    const loadFactor =
      loadScore > 0.80 ? 0.5
      : loadScore > 0.60 ? 0.75
      : 1.0;

    // Depth factor: increase concurrency when queue is deep
    const depthFactor =
      depth > 500 ? 1.5
      : depth > 100 ? 1.2
      : 1.0;

    const adjusted = Math.round(base * loadFactor * depthFactor);
    const result = Math.max(1, Math.min(adjusted, base * 2));

    this.logger.debug(
      { queue, base, loadScore, depth, loadFactor, depthFactor, result },
      'Adaptive concurrency computed',
    );

    return result;
  }

  /** Return the base (non-adaptive) concurrency for a queue. */
  getBaseConcurrency(queue: string): number {
    return QUEUE_CONCURRENCY[queue] ?? 5;
  }

  /** List all known queues. */
  getKnownQueues(): string[] {
    return Object.keys(QUEUE_CONCURRENCY);
  }
}

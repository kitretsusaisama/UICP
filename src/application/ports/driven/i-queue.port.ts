/**
 * Options for a one-time enqueue operation.
 */
export interface EnqueueOptions {
  /** Job priority — higher values are processed first. */
  priority?: number;
  /** Delay before the job becomes available (milliseconds). */
  delayMs?: number;
  /** Maximum number of retry attempts on failure. */
  maxAttempts?: number;
}

/**
 * Options for a repeatable (scheduled) job.
 */
export interface RepeatableJobOptions {
  /** Cron expression (e.g. '0 * /6 * * *' for every 6 hours — without the space). */
  cron: string;
  /** Unique key to identify and deduplicate the repeatable job. */
  jobKey: string;
  /** Maximum number of retry attempts per execution. */
  maxAttempts?: number;
}

/**
 * Driven port — BullMQ job queue.
 *
 * Contract:
 * - `enqueue` adds a one-time job to the named queue.
 * - `enqueueRepeatable` registers a cron-scheduled job (idempotent by `jobKey`).
 * - Per-queue concurrency limits are configured at the worker level (Section 11.2).
 */
export interface IQueuePort {
  /**
   * Enqueue a one-time job on the specified queue.
   */
  enqueue(queue: string, payload: Record<string, unknown>, options?: EnqueueOptions): Promise<void>;

  /**
   * Register or update a repeatable (cron-scheduled) job.
   * Idempotent — calling with the same `jobKey` updates the existing schedule.
   */
  enqueueRepeatable(
    queue: string,
    payload: Record<string, unknown>,
    options: RepeatableJobOptions,
  ): Promise<void>;
}

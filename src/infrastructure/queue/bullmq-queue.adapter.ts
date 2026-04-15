import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Queue, JobsOptions } from 'bullmq';
import {
  EnqueueOptions,
  IQueuePort,
  RepeatableJobOptions,
} from '../../application/ports/driven/i-queue.port';

/**
 * Per-queue concurrency limits (Section 11.2 — Bulkhead Pattern).
 * Workers read this map to configure their own concurrency.
 */
export const QUEUE_CONCURRENCY: Record<string, number> = {
  'otp-send': 5,       // OTP delivery — low concurrency, high priority
  'audit-write': 20,   // Audit log writes — high throughput, low priority
  'soc-alert': 3,      // SOC alert processing — low concurrency
  'outbox-relay': 10,  // Outbox relay — medium concurrency
  'email-welcome': 5,  // Welcome emails — low priority
};

/**
 * Queue names as constants to avoid magic strings.
 */
export const QUEUE_NAMES = {
  OTP_SEND: 'otp-send',
  AUDIT_WRITE: 'audit-write',
  SOC_ALERT: 'soc-alert',
  OUTBOX_RELAY: 'outbox-relay',
  EMAIL_WELCOME: 'email-welcome',
} as const;

/**
 * BullMQ queue adapter implementing IQueuePort.
 *
 * - Wraps BullMQ `Queue` instances with per-queue concurrency limits (Section 11.2).
 * - `enqueueRepeatable()` registers cron-scheduled jobs (idempotent by jobKey).
 * - Queues are lazily created on first use and cached.
 *
 * Implements: Req 4.5, Req 15 (resilience via BullMQ retry/backoff)
 */
@Injectable()
export class BullMqQueueAdapter implements IQueuePort, OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(BullMqQueueAdapter.name);
  private readonly queues = new Map<string, Queue>();

  private readonly connection: { host: string; port: number; password?: string; tls?: object };

  constructor(private readonly config: ConfigService) {
    this.connection = {
      host: this.config.get<string>('REDIS_HOST') ?? 'localhost',
      port: this.config.get<number>('REDIS_PORT') ?? 6379,
      password: this.config.get<string>('REDIS_PASSWORD'),
      tls: this.config.get<string>('REDIS_TLS') === 'true' ? {} : undefined,
    };
  }

  onModuleInit(): void {
    // Pre-create all known queues so they are ready before first use
    for (const name of Object.values(QUEUE_NAMES)) {
      this.getOrCreateQueue(name);
    }
    this.logger.log('BullMQ queue adapter initialized');
  }

  async onModuleDestroy(): Promise<void> {
    await Promise.all([...this.queues.values()].map((q) => q.close()));
    this.logger.log('BullMQ queues closed');
  }

  // ── IQueuePort ─────────────────────────────────────────────────────────────

  /**
   * Enqueue a one-time job on the specified queue.
   */
  async enqueue(
    queue: string,
    payload: Record<string, unknown>,
    options?: EnqueueOptions,
  ): Promise<void> {
    const q = this.getOrCreateQueue(queue);

    const jobOptions: JobsOptions = {
      priority: options?.priority,
      delay: options?.delayMs,
      attempts: options?.maxAttempts ?? 3,
      backoff: { type: 'exponential', delay: 1_000 },
      removeOnComplete: { count: 1_000 },
      removeOnFail: { count: 5_000 },
    };

    await q.add(queue, payload, jobOptions);
    this.logger.debug({ queue, payload }, 'Job enqueued');
  }

  /**
   * Register or update a repeatable (cron-scheduled) job.
   * Idempotent — calling with the same `jobKey` updates the existing schedule.
   */
  async enqueueRepeatable(
    queue: string,
    payload: Record<string, unknown>,
    options: RepeatableJobOptions,
  ): Promise<void> {
    const q = this.getOrCreateQueue(queue);

    await q.add(options.jobKey, payload, {
      repeat: { pattern: options.cron },
      jobId: options.jobKey, // deduplication key
      attempts: options.maxAttempts ?? 3,
      backoff: { type: 'exponential', delay: 1_000 },
      removeOnComplete: { count: 100 },
      removeOnFail: { count: 500 },
    });

    this.logger.log({ queue, jobKey: options.jobKey, cron: options.cron }, 'Repeatable job registered');
  }

  // ── Internal ───────────────────────────────────────────────────────────────

  private getOrCreateQueue(name: string): Queue {
    let q = this.queues.get(name);
    if (!q) {
      q = new Queue(name, {
        connection: this.connection,
        defaultJobOptions: {
          removeOnComplete: { count: 1_000 },
          removeOnFail: { count: 5_000 },
          attempts: 3,
          backoff: { type: 'exponential', delay: 1_000 },
        },
      });

      q.on('error', (err) => {
        this.logger.error({ queue: name, err }, 'BullMQ queue error');
      });

      this.queues.set(name, q);
      this.logger.debug({ queue: name }, 'BullMQ queue created');
    }
    return q;
  }

  /** Expose a queue instance for workers that need direct access (e.g. outbox relay). */
  getQueue(name: string): Queue {
    return this.getOrCreateQueue(name);
  }
}

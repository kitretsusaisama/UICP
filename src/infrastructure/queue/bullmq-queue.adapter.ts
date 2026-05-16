import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Queue, JobsOptions } from 'bullmq';
import {
  EnqueueOptions,
  IQueuePort,
  RepeatableJobOptions,
} from '../../application/ports/driven/i-queue.port';

export const QUEUE_CONCURRENCY: Record<string, number> = {
  'otp-send': 5,
  'otp-retry': 5,
  'otp-fallback': 5,
  'otp-cleanup': 2,
  'email-send': 10,
  'email-batch': 5,
  'email-retry': 5,
  'email-fallback': 5,
  'email-webhook': 10,
  'provider-health-check': 3,
  'provider-circuit-probe': 2,
  'communication-dead-letter': 2,
  'audit-write': 20,
  'soc-alert': 3,
  'outbox-relay': 10,
  'email-welcome': 5,
};

export const QUEUE_NAMES = {
  OTP_SEND: 'otp-send',
  OTP_RETRY: 'otp-retry',
  OTP_FALLBACK: 'otp-fallback',
  OTP_CLEANUP: 'otp-cleanup',
  EMAIL_SEND: 'email-send',
  EMAIL_BATCH: 'email-batch',
  EMAIL_RETRY: 'email-retry',
  EMAIL_FALLBACK: 'email-fallback',
  EMAIL_WEBHOOK: 'email-webhook',
  PROVIDER_HEALTH_CHECK: 'provider-health-check',
  PROVIDER_CIRCUIT_PROBE: 'provider-circuit-probe',
  COMMUNICATION_DEAD_LETTER: 'communication-dead-letter',
  AUDIT_WRITE: 'audit-write',
  SOC_ALERT: 'soc-alert',
  OUTBOX_RELAY: 'outbox-relay',
  EMAIL_WELCOME: 'email-welcome',
} as const;

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
    for (const name of Object.values(QUEUE_NAMES)) {
      this.getOrCreateQueue(name);
    }
    this.logger.log('BullMQ queue adapter initialized');
  }

  async onModuleDestroy(): Promise<void> {
    await Promise.all([...this.queues.values()].map((queue) => queue.close()));
    this.logger.log('BullMQ queues closed');
  }

  async enqueue(
    queue: string,
    payload: Record<string, unknown>,
    options?: EnqueueOptions,
  ): Promise<void> {
    const q = this.getOrCreateQueue(queue);
    await this.assertQueueHasCapacity(q, queue);

    const jobOptions: JobsOptions = {
      priority: options?.priority,
      delay: options?.delayMs,
      attempts: options?.maxAttempts ?? 3,
      backoff: { type: 'exponential', delay: 1_000 },
      jobId: options?.idempotencyKey,
      removeOnComplete: { count: 1_000 },
      removeOnFail: { count: 5_000 },
    };

    await q.add(queue, payload, jobOptions);
    this.logger.debug({ queue }, 'Job enqueued');
  }

  async enqueueRepeatable(
    queue: string,
    payload: Record<string, unknown>,
    options: RepeatableJobOptions,
  ): Promise<void> {
    const q = this.getOrCreateQueue(queue);

    await q.add(options.jobKey, payload, {
      repeat: { pattern: options.cron },
      jobId: options.jobKey,
      attempts: options.maxAttempts ?? 3,
      backoff: { type: 'exponential', delay: 1_000 },
      removeOnComplete: { count: 100 },
      removeOnFail: { count: 500 },
    });

    this.logger.log({ queue, jobKey: options.jobKey, cron: options.cron }, 'Repeatable job registered');
  }

  getQueue(name: string): Queue {
    return this.getOrCreateQueue(name);
  }

  private async assertQueueHasCapacity(queue: Queue, name: string): Promise<void> {
    const maxQueueLen = this.config.get<number>('BULLMQ_MAX_QUEUE_LEN') ?? 50_000;
    const sampleRate = this.config.get<number>('BULLMQ_QUEUE_LEN_SAMPLE_RATE') ?? 100;
    if (sampleRate <= 0 || Math.floor(Math.random() * sampleRate) !== 0) {
      return;
    }

    const count = await queue.getJobCountByTypes('wait', 'paused', 'delayed');
    if (count < maxQueueLen) {
      return;
    }

    this.logger.error({ queue: name, maxQueueLen, count }, 'Queue capacity exceeded');
    const error: Error & { code?: string } = new Error(
      `QUEUE_FULL: The queue ${name} has reached its maximum capacity of ${maxQueueLen}`,
    );
    error.code = 'QUEUE_FULL';
    throw error;
  }

  private getOrCreateQueue(name: string): Queue {
    let queue = this.queues.get(name);
    if (!queue) {
      queue = new Queue(name, {
        connection: this.connection,
        defaultJobOptions: {
          removeOnComplete: { count: 1_000 },
          removeOnFail: { count: 5_000 },
          attempts: 3,
          backoff: { type: 'exponential', delay: 1_000 },
        },
      });

      queue.on('error', (err) => {
        this.logger.error({ queue: name, err }, 'BullMQ queue error');
      });

      this.queues.set(name, queue);
      this.logger.debug({ queue: name }, 'BullMQ queue created');
    }
    return queue;
  }
}

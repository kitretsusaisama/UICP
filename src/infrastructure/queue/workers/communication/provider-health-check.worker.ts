import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Job, Worker } from 'bullmq';
import { QUEUE_CONCURRENCY, QUEUE_NAMES } from '../../bullmq-queue.adapter';

@Injectable()
export class ProviderHealthCheckWorker implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ProviderHealthCheckWorker.name);
  private worker?: Worker;

  constructor(private readonly config: ConfigService) {}

  onModuleInit(): void {
    const connection = {
      host: this.config.get<string>('REDIS_HOST') ?? 'localhost',
      port: this.config.get<number>('REDIS_PORT') ?? 6379,
      password: this.config.get<string>('REDIS_PASSWORD'),
      tls: this.config.get<string>('REDIS_TLS') === 'true' ? {} : undefined,
    };

    this.worker = new Worker(
      QUEUE_NAMES.PROVIDER_HEALTH_CHECK,
      async (job: Job) => this.process(job),
      {
        connection,
        concurrency: QUEUE_CONCURRENCY[QUEUE_NAMES.PROVIDER_HEALTH_CHECK],
      },
    );
  }

  async onModuleDestroy(): Promise<void> {
    await this.worker?.close();
  }

  private async process(job: Job): Promise<void> {
    this.logger.debug({ jobId: job.id }, 'Provider health check placeholder processed');
  }
}

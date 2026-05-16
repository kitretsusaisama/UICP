import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Job, Worker } from 'bullmq';
import { CommunicationJobPayload } from '../../../../application/communication/communication.types';
import { QUEUE_CONCURRENCY, QUEUE_NAMES } from '../../bullmq-queue.adapter';

@Injectable()
export class EmailSendWorker implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(EmailSendWorker.name);
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
      QUEUE_NAMES.EMAIL_SEND,
      async (job: Job<CommunicationJobPayload>) => this.process(job),
      {
        connection,
        concurrency: QUEUE_CONCURRENCY[QUEUE_NAMES.EMAIL_SEND],
      },
    );
  }

  async onModuleDestroy(): Promise<void> {
    await this.worker?.close();
  }

  private async process(job: Job<CommunicationJobPayload>): Promise<void> {
    this.logger.debug(
      {
        tenantId: job.data.tenantId,
        providerName: job.data.providerName,
        lineageId: job.data.lineageId,
      },
      'Email send job accepted by communication runtime',
    );
  }
}

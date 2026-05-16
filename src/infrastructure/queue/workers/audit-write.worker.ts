import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Worker, Job } from 'bullmq';
import { randomUUID } from 'crypto';
import {
  AuditLogRecord,
  IAuditLogRepository,
} from '../../../application/ports/driven/i-audit-log.repository';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { QUEUE_CONCURRENCY, QUEUE_NAMES } from '../bullmq-queue.adapter';
import { IMetricsPort } from '../../../application/ports/driven/i-metrics.port';

@Injectable()
export class AuditWriteWorker implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AuditWriteWorker.name);
  private worker!: Worker;

  constructor(
    @Inject(INJECTION_TOKENS.AUDIT_LOG_REPOSITORY)
    private readonly auditRepo: IAuditLogRepository,
    private readonly config: ConfigService,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {}

  onModuleInit(): void {
    const connection = {
      host: this.config.get<string>('REDIS_HOST') ?? 'localhost',
      port: this.config.get<number>('REDIS_PORT') ?? 6379,
      password: this.config.get<string>('REDIS_PASSWORD'),
      tls: this.config.get<string>('REDIS_TLS') === 'true' ? {} : undefined,
    };

    this.worker = new Worker(
      QUEUE_NAMES.AUDIT_WRITE,
      async (job: Job) => this.process(job),
      {
        connection,
        concurrency: QUEUE_CONCURRENCY[QUEUE_NAMES.AUDIT_WRITE],
      },
    );

    this.worker.on('failed', (job, err) => {
      this.logger.error({ jobId: job?.id, err }, 'Audit write job failed');
      this.metrics?.increment('uicp_audit_write_failures_total');
    });
  }

  async onModuleDestroy(): Promise<void> {
    await this.worker.close();
  }

  private async process(job: Job): Promise<void> {
    const event = job.data as Record<string, any>;
    const tenantId = String(event.tenantId ?? '00000000-0000-4000-8000-000000000000');
    const record: AuditLogRecord = {
      id: randomUUID(),
      tenantId,
      actorId: event.actorId ?? event.payload?.userId,
      actorType: event.actorType ?? 'system',
      action: String(event.eventType ?? event.action ?? job.name),
      resourceType: String(event.aggregateType ?? event.resourceType ?? 'event'),
      resourceId: event.aggregateId ?? event.resourceId,
      metadataEnc: JSON.stringify(event.payload ?? event),
      checksum: '',
      createdAt: event.createdAt ? new Date(event.createdAt) : new Date(),
    };

    await this.auditRepo.save(record);
    this.metrics?.increment('uicp_audit_events_written_total');
  }
}

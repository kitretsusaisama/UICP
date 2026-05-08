import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Worker, Job } from 'bullmq';
import { randomUUID, createHash } from 'crypto';
import { IAuditLogRepository } from '../../../domain/repositories/audit-log.repository.interface';
import { AuditLog } from '../../../domain/entities/audit-log.entity';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { QUEUE_CONCURRENCY, QUEUE_NAMES } from '../bullmq-queue.adapter';
import { IMetricsPort } from '../../../application/ports/driven/i-metrics.port';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

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

    this.logger.log(`AuditWriteWorker started (concurrency=${QUEUE_CONCURRENCY[QUEUE_NAMES.AUDIT_WRITE]})`);
  }

  async onModuleDestroy(): Promise<void> {
    await this.worker.close();
    this.logger.log('AuditWriteWorker stopped');
  }

  private async process(job: Job): Promise<void> {
    const start = Date.now();
    const event = job.data;

    // Hash Chain Logic (Req 10.3)
    // hash_n = SHA256(prev_hash + event_data)

    const latestLog = await this.auditRepo.getLatestLog(event.tenantId);
    const prevHash = latestLog ? latestLog.hash : null;

    // Canonicalization (sorted keys to avoid whitespace variance)
    const canonicalEvent = JSON.stringify(event, Object.keys(event).sort());

    const hashInput = (prevHash || '') + canonicalEvent;
    const hash = createHash('sha256').update(hashInput).digest('hex');

    const auditLog = new AuditLog({
      id: randomUUID(),
      tenantId: event.tenantId,
      actorId: event.payload?.userId ?? event.aggregateId, // Best effort from outbox shape
      action: event.eventType,
      targetType: event.aggregateType,
      targetId: event.aggregateId,
      metadata: event.payload ?? {},
      hash,
      prevHash,
      createdAt: new Date(event.createdAt),
    });

    await this.auditRepo.save(auditLog);

    const elapsed = Date.now() - start;
    this.metrics?.histogram('uicp_audit_write_duration_ms', elapsed);
    this.metrics?.increment('uicp_audit_events_written_total');
  }
}

import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Worker, Job } from 'bullmq';
import { createHmac, randomUUID } from 'crypto';
import { MYSQL_POOL, DbPool } from '../../db/mysql/mysql.module';
import { QUEUE_CONCURRENCY, QUEUE_NAMES } from '../bullmq-queue.adapter';

export interface AuditWriteJobPayload {
  tenantId: string;
  actorId?: string;
  actorType: 'user' | 'system' | 'admin';
  action: string;
  resourceType: string;
  resourceId?: string;
  /** Already-encrypted metadata (base64 encoded). */
  metadataEnc?: string;
  metadataEncKid?: string;
  ipHash?: string;
}

/**
 * BullMQ worker for the `audit-write` queue.
 *
 * - Concurrency: 20 (Section 11.2 bulkhead — high throughput, low priority)
 * - Writes audit log entries to `audit_logs` table with HMAC-SHA256 checksum.
 * - Audit logs are INSERT-only (immutable) — Req 12.1.
 * - HMAC checksum computed over immutable fields for tamper detection — Req 12.10.
 *
 * Implements: Req 12.1, Req 12.10, Req 4.5
 */
@Injectable()
export class AuditWriteWorker implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AuditWriteWorker.name);
  private worker!: Worker;

  private readonly connection: { host: string; port: number; password?: string; tls?: object };

  /** HMAC key for audit log checksum — loaded from env. */
  private readonly hmacKey: string;

  constructor(
    @Inject(MYSQL_POOL) private readonly pool: DbPool,
    private readonly config: ConfigService,
  ) {
    this.connection = {
      host: this.config.get<string>('REDIS_HOST') ?? 'localhost',
      port: this.config.get<number>('REDIS_PORT') ?? 6379,
      password: this.config.get<string>('REDIS_PASSWORD'),
      tls: this.config.get<string>('REDIS_TLS') === 'true' ? {} : undefined,
    };
    this.hmacKey = this.config.get<string>('AUDIT_HMAC_KEY') ?? 'default-audit-hmac-key';
  }

  onModuleInit(): void {
    this.worker = new Worker(
      QUEUE_NAMES.AUDIT_WRITE,
      async (job: Job<AuditWriteJobPayload>) => this.process(job),
      {
        connection: this.connection,
        concurrency: QUEUE_CONCURRENCY[QUEUE_NAMES.AUDIT_WRITE],
      },
    );

    this.worker.on('completed', (job) => {
      this.logger.debug({ jobId: job.id }, 'Audit write job completed');
    });

    this.worker.on('failed', (job, err) => {
      this.logger.error({ jobId: job?.id, err }, 'Audit write job failed');
    });

    this.logger.log(`AuditWriteWorker started (concurrency=${QUEUE_CONCURRENCY[QUEUE_NAMES.AUDIT_WRITE]})`);
  }

  async onModuleDestroy(): Promise<void> {
    await this.worker.close();
    this.logger.log('AuditWriteWorker stopped');
  }

  // ── Job Processor ──────────────────────────────────────────────────────────

  private async process(job: Job<AuditWriteJobPayload>): Promise<void> {
    const {
      tenantId,
      actorId,
      actorType,
      action,
      resourceType,
      resourceId,
      metadataEnc,
      metadataEncKid,
      ipHash,
    } = job.data;

    const id = randomUUID().replace(/-/g, '');
    const createdAt = new Date();

    // Compute HMAC-SHA256 over immutable fields (Req 12.10)
    const checksumInput = [
      id,
      tenantId,
      actorId ?? '',
      actorType,
      action,
      resourceType,
      resourceId ?? '',
      createdAt.toISOString(),
    ].join('|');

    const checksum = createHmac('sha256', this.hmacKey)
      .update(checksumInput)
      .digest();

    await this.pool.execute(
      `INSERT INTO audit_logs
         (id, tenant_id, actor_id, actor_type, action, resource_type, resource_id,
          metadata_enc, metadata_enc_kid, ip_hash, checksum, created_at)
       VALUES
         (UNHEX(?), UNHEX(?), UNHEX(?), ?, ?, ?, UNHEX(?), ?, ?, UNHEX(?), ?, ?)`,
      [
        id,
        tenantId.replace(/-/g, ''),
        actorId ? actorId.replace(/-/g, '') : null,
        actorType,
        action,
        resourceType,
        resourceId ? resourceId.replace(/-/g, '') : null,
        metadataEnc ?? null,
        metadataEncKid ?? null,
        ipHash ?? null,
        checksum,
        createdAt,
      ],
    );

    this.logger.debug({ jobId: job.id, action, resourceType }, 'Audit log written');
  }
}

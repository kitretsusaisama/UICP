import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Worker, Job } from 'bullmq';
import { randomUUID, createHash } from 'crypto';
import { ISocAlertRepository } from '../../../domain/repositories/soc/soc-alert.repository.interface';
import { SocAlert } from '../../../domain/entities/soc/soc-alert.entity';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { QUEUE_CONCURRENCY, QUEUE_NAMES } from '../bullmq-queue.adapter';
import { IMetricsPort } from '../../../application/ports/driven/i-metrics.port';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import Redis from 'ioredis';

@Injectable()
export class SocAlertWorker implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(SocAlertWorker.name);
  private worker!: Worker;
  private redisClient!: Redis;
  private readonly connection: { host: string; port: number; password?: string; tls?: object };

  constructor(
    @Inject('SOC_ALERT_REPOSITORY') private readonly socAlertRepo: ISocAlertRepository,
    private readonly config: ConfigService,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {
    this.connection = {
      host: this.config.get<string>('REDIS_HOST') ?? 'localhost',
      port: this.config.get<number>('REDIS_PORT') ?? 6379,
      password: this.config.get<string>('REDIS_PASSWORD'),
      tls: this.config.get<string>('REDIS_TLS') === 'true' ? {} : undefined,
    };
  }

  onModuleInit(): void {
    this.redisClient = new Redis(this.connection);

    this.worker = new Worker(
      QUEUE_NAMES.SOC_ALERT,
      async (job: Job) => this.process(job),
      {
        connection: this.connection,
        concurrency: QUEUE_CONCURRENCY[QUEUE_NAMES.SOC_ALERT],
      },
    );

    this.worker.on('failed', (job, err) => {
      this.logger.error({ jobId: job?.id, err }, 'SOC alert job failed');
      this.metrics?.increment('uicp_soc_alert_failures_total');
    });

    this.logger.log(`SocAlertWorker started (concurrency=${QUEUE_CONCURRENCY[QUEUE_NAMES.SOC_ALERT]})`);
  }

  async onModuleDestroy(): Promise<void> {
    await this.worker.close();
    await this.redisClient.quit();
    this.logger.log('SocAlertWorker stopped');
  }

  private async process(job: Job): Promise<void> {
    const alert = job.data;

    // Deduplication logic: prevents alert storms
    // dedupe_key = SHA256(tenantId + type + target + time_bucket(hours))
    const timeBucket = new Date().toISOString().slice(0, 13); // yyyy-mm-ddThh
    const dedupeString = `${alert.tenantId}:${alert.type}:${alert.userId}:${timeBucket}`;
    const dedupeKey = createHash('sha256').update(dedupeString).digest('hex');

    const socAlert = new SocAlert({
      id: randomUUID(),
      tenantId: alert.tenantId,
      type: alert.type,
      severity: alert.severity || 'MEDIUM',
      dedupeKey,
      payload: alert.payload || {},
      status: 'OPEN',
    });

    try {
      await this.socAlertRepo.save(socAlert);
      this.metrics?.increment('uicp_soc_alerts_created_total', { severity: socAlert.severity });

      // Phase 6 AUTO-REMEDIATION Matrix
      await this.autoRemediate(alert);
    } catch (e: any) {
      if (e.code === 'ER_DUP_ENTRY') {
        // Idempotent success (Deduplication constraint fired)
        this.logger.debug({ dedupeKey }, 'Duplicate alert dropped silently');
        return;
      }
      throw e;
    }
  }

  private async autoRemediate(alert: any) {
    if (alert.type === 'TOKEN_REUSE' || alert.type === 'CREDENTIAL_STUFFING_DETECTED') {
      this.logger.warn({ userId: alert.userId }, 'AUTO-REMEDIATION: Triggering global session revocation for compromised account');

      const zsetKey = `user_sessions:${alert.userId}`;
      const luaScript = `
        local sids = redis.call('ZRANGE', KEYS[1], 0, -1)
        for i, sid in ipairs(sids) do
          local sessionKey = 'session:' .. sid
          local jti = redis.call('HGET', sessionKey, 'jti')
          if jti then
             redis.call('SET', 'jti_block:' .. jti, '1', 'EX', 86400)
          end
          redis.call('DEL', sessionKey)
        end
        redis.call('DEL', KEYS[1])
        redis.call('SET', 'user_block:' .. KEYS[1], '1', 'EX', 300) -- short TTL lock
        return 1
      `;

      await this.redisClient.eval(luaScript, 1, zsetKey);
    }
  }
}

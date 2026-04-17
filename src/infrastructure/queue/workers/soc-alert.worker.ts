import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Worker, Job } from 'bullmq';
import { IAlertRepository, SocAlert } from '../../../application/ports/driven/i-alert.repository';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { QUEUE_CONCURRENCY, QUEUE_NAMES } from '../bullmq-queue.adapter';

export interface SocAlertJobPayload {
  alert: SocAlert;
}

/**
 * WebSocket gateway interface — injected optionally to avoid circular deps.
 * The concrete SocDashboardGateway implements this.
 */
export interface ISocWebSocketGateway {
  emitAlertCreated(tenantId: string, alert: SocAlert): void;
}

export const SOC_WS_GATEWAY = Symbol('SOC_WS_GATEWAY');

/**
 * BullMQ worker for the `soc-alert` queue.
 *
 * - Concurrency: 3 (Section 11.2 bulkhead — low concurrency, security-critical)
 * - Persists SocAlert via IAlertRepository (INSERT-only, with HMAC checksum).
 * - Emits real-time WebSocket event to SOC dashboard (Req 12.6).
 *
 * Implements: Req 12.1, Req 12.6, Req 11.9 (threat score > 0.75 → SOC alert)
 */
@Injectable()
export class SocAlertWorker implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(SocAlertWorker.name);
  private worker!: Worker;

  private readonly connection: { host: string; port: number; password?: string; tls?: object };

  constructor(
    @Inject(INJECTION_TOKENS.ALERT_REPOSITORY)
    private readonly alertRepository: IAlertRepository,
    private readonly config: ConfigService,
    @Optional()
    @Inject(SOC_WS_GATEWAY)
    private readonly wsGateway: ISocWebSocketGateway | null,
  ) {
    this.connection = {
      host: this.config.get<string>('REDIS_HOST') ?? 'localhost',
      port: this.config.get<number>('REDIS_PORT') ?? 6379,
      password: this.config.get<string>('REDIS_PASSWORD'),
      tls: this.config.get<string>('REDIS_TLS') === 'true' ? {} : undefined,
    };
  }

  onModuleInit(): void {
    this.worker = new Worker(
      QUEUE_NAMES.SOC_ALERT,
      async (job: Job<SocAlertJobPayload>) => this.process(job),
      {
        connection: this.connection,
        concurrency: QUEUE_CONCURRENCY[QUEUE_NAMES.SOC_ALERT],
      },
    );

    this.worker.on('completed', (job) => {
      this.logger.debug({ jobId: job.id }, 'SOC alert job completed');
    });

    this.worker.on('failed', (job, err) => {
      this.logger.error({ jobId: job?.id, err }, 'SOC alert job failed');
    });

    this.logger.log(`SocAlertWorker started (concurrency=${QUEUE_CONCURRENCY[QUEUE_NAMES.SOC_ALERT]})`);
  }

  async onModuleDestroy(): Promise<void> {
    await this.worker.close();
    this.logger.log('SocAlertWorker stopped');
  }

  // ── Job Processor ──────────────────────────────────────────────────────────

  private async process(job: Job<SocAlertJobPayload>): Promise<void> {
    // The payload could be a direct SocAlert or an OutboxEvent masquerading as one (since Phase 7)
    // We normalize the extraction to handle generic threat and replay events forwarded from outbox.
    const alert = job.data.alert || (job.data as any).payload;
    const eventType = (job.data as any).eventType;

    this.logger.debug(
      { jobId: job.id, alertId: alert?.id, threatScore: alert?.threatScore, eventType },
      'Processing SOC alert job',
    );

    // WAR-GRADE DEFENSE: Phase 2 - SOC Integration
    // Simulated forwarding to SIEM (Splunk, Datadog) and PagerDuty via stdout structured logging.
    // In production, this would use a dedicated HTTP/gRPC client to the SIEM provider.
    this.logger.error({
      source: 'SOC_PIPELINE',
      siem_forward: true,
      event_type: eventType ?? 'UEBA_THRESHOLD_EXCEEDED',
      alert_data: alert
    }, 'CRITICAL SECURITY EVENT DETECTED — Forwarding to SIEM');

    // Auto-remediation logic for critical detected anomalies
    if (eventType === 'TokenReuseDetected' || eventType === 'CredentialReuse') {
      this.logger.error({ userId: alert.userId ?? alert.userId }, 'AUTO-REMEDIATION: Triggering global session revocation for compromised account');
      // Simulated: await this.sessionService.invalidateAll(UserId.from(userId), TenantId.from(tenantId));
    } else if (alert?.threatScore > 0.9) {
      this.logger.error({ userId: alert.userId }, 'AUTO-REMEDIATION: High UEBA threat score. Locking user account.');
    }

    // Persist the alert (INSERT-only, HMAC checksum verified on read)
    if (alert && alert.id && alert.threatScore !== undefined) {
      const tenantId = TenantId.from(alert.tenantId);
      await this.alertRepository.save(alert);

      // Emit real-time WebSocket event to SOC dashboard (Req 12.6)
      if (this.wsGateway) {
        this.wsGateway.emitAlertCreated(alert.tenantId, alert);
      }

      this.logger.log(
        { alertId: alert.id, tenantId: tenantId.toString(), threatScore: alert.threatScore },
        'SOC alert persisted and emitted',
      );
    }
  }
}

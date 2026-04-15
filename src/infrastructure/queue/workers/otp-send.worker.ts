import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Worker, Job } from 'bullmq';
import { IOtpPort, SendOtpParams } from '../../../application/ports/driven/i-otp.port';
import { OtpDispatchPayload } from '../../../application/contracts/otp-dispatch.contract';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { QUEUE_CONCURRENCY, QUEUE_NAMES } from '../bullmq-queue.adapter';

/**
 * BullMQ worker for the `otp-send` queue.
 *
 * - Concurrency: 5 (Section 11.2 bulkhead)
 * - Priority: 1 (highest — OTP delivery is time-sensitive)
 * - Dispatches OTP codes via IOtpPort (Firebase SMS or SMTP email)
 *
 * Implements: Req 6.1 (OTP delivery), Req 15 (resilience via circuit breaker in IOtpPort)
 */
@Injectable()
export class OtpSendWorker implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(OtpSendWorker.name);
  private worker!: Worker;

  private readonly connection: { host: string; port: number; password?: string; tls?: object };

  constructor(
    @Inject(INJECTION_TOKENS.OTP_PORT)
    private readonly otpPort: IOtpPort,
    private readonly config: ConfigService,
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
      QUEUE_NAMES.OTP_SEND,
      async (job: Job<OtpDispatchPayload>) => this.process(job),
      {
        connection: this.connection,
        concurrency: QUEUE_CONCURRENCY[QUEUE_NAMES.OTP_SEND],
      },
    );

    this.worker.on('completed', (job) => {
      this.logger.debug({ jobId: job.id }, 'OTP send job completed');
    });

    this.worker.on('failed', (job, err) => {
      this.logger.error({ jobId: job?.id, err }, 'OTP send job failed');
    });

    this.logger.log(`OtpSendWorker started (concurrency=${QUEUE_CONCURRENCY[QUEUE_NAMES.OTP_SEND]})`);
  }

  async onModuleDestroy(): Promise<void> {
    await this.worker.close();
    this.logger.log('OtpSendWorker stopped');
  }

  // ── Job Processor ──────────────────────────────────────────────────────────

  private async process(job: Job<OtpDispatchPayload>): Promise<void> {
    const { recipient, channel, purpose, code, tenantName, tenantId } = job.data;

    this.logger.debug({ jobId: job.id, channel, purpose }, 'Processing OTP send job');

    const params: SendOtpParams = { tenantId: tenantId ?? '00000000-0000-4000-8000-000000000000', recipient, channel, purpose, code, tenantName };
    await this.otpPort.send(params);
  }
}

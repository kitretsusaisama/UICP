import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Worker, Job } from 'bullmq';
import { IOtpPort, SendOtpParams } from '../../../application/ports/driven/i-otp.port';
import { OtpDispatchPayload } from '../../../application/contracts/otp-dispatch.contract';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { QUEUE_CONCURRENCY, QUEUE_NAMES } from '../bullmq-queue.adapter';
import Redis from 'ioredis';

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
  private redisClient!: Redis;

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
    this.redisClient = new Redis(this.connection);

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
    await this.redisClient.quit();
    this.logger.log('OtpSendWorker stopped');
  }

  // ── Job Processor ──────────────────────────────────────────────────────────

  private async process(job: Job<OtpDispatchPayload>): Promise<void> {
    const { recipient, channel, purpose, code, tenantName, tenantId } = job.data;

    this.logger.debug({ jobId: job.id, channel, purpose }, 'Processing OTP send job');

    const effectiveTenantId = tenantId ?? '00000000-0000-4000-8000-000000000000';

    // WAR-GRADE DEFENSE: Tenant Cost Controller
    // Before sending an SMS, check if the tenant has exceeded their daily SMS limit.
    if (channel === 'SMS') {
      try {
        const costKey = `tenant:spend:sms:${effectiveTenantId}:${new Date().toISOString().split('T')[0]}`;

        // Use Lua script to atomically check and increment spend limit (max 1000 SMS per day)
        const luaScript = `
          local current = tonumber(redis.call('get', KEYS[1]) or "0")
          if current >= tonumber(ARGV[1]) then
            return -1
          else
            redis.call('incr', KEYS[1])
            redis.call('expire', KEYS[1], 86400)
            return current + 1
          end
        `;
        const currentSpend = await this.redisClient.eval(luaScript, 1, costKey, 1000);

        if (currentSpend === -1) {
          this.logger.error({ tenantId: effectiveTenantId }, 'SMS DISPATCH BLOCKED: Tenant exceeded daily SMS budget');
          throw new Error('QUOTA_EXCEEDED: Tenant daily SMS budget exceeded');
        }
      } catch (err: any) {
        if (err.message.includes('QUOTA_EXCEEDED')) {
          throw err;
        }
        this.logger.warn({ err }, 'Failed to check tenant SMS quota — fail closed for safety');
        throw new Error('QUOTA_CHECK_FAILED: SMS quota check failed');
      }
    }

    const params: SendOtpParams = { tenantId: effectiveTenantId, recipient, channel, purpose, code, tenantName };
    await this.otpPort.send(params);
  }
}

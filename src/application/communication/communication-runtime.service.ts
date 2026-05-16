import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { OtpService, OtpPurpose } from '../services/otp.service';
import { IQueuePort } from '../ports/driven/i-queue.port';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { QUEUE_NAMES } from '../../infrastructure/queue/bullmq-queue.adapter';
import { CommunicationChannel, CommunicationPurpose, CommunicationJobPayload } from './communication.types';
import { TenantProviderResolver } from './provider-resolver.service';

function toOtpPurpose(purpose: CommunicationPurpose): OtpPurpose {
  if (purpose === 'PASSWORD_RESET') return 'PASSWORD_RESET';
  if (purpose === 'MFA' || purpose === 'SECURITY_ALERT') return 'MFA';
  return 'IDENTITY_VERIFICATION';
}

@Injectable()
export class CommunicationRuntime {
  constructor(
    private readonly otp: OtpService,
    private readonly resolver: TenantProviderResolver,
    @Inject(INJECTION_TOKENS.QUEUE_PORT) private readonly queue: IQueuePort,
  ) {}

  async sendOtp(input: {
    tenantId: string;
    userId: string;
    recipient: string;
    channel: CommunicationChannel;
    purpose: CommunicationPurpose;
    tenantName?: string;
    traceId?: string;
  }) {
    const code = this.otp.generate();
    const otpPurpose = toOtpPurpose(input.purpose);
    await this.otp.store(input.userId, otpPurpose, code);

    const resolution = await this.resolver.resolve(input);
    const challengeId = randomUUID();
    const idempotencyKey = `otp:${input.tenantId}:${input.userId}:${input.purpose}:${challengeId}`;
    const job: CommunicationJobPayload = {
      tenantId: input.tenantId,
      lineageId: resolution.lineageId,
      idempotencyKey,
      providerName: resolution.primary.providerName,
      channel: input.channel,
      purpose: input.purpose,
      recipient: input.recipient,
      attempt: 1,
      maxAttempts: resolution.policy.maxRetries + 1,
      createdAt: new Date().toISOString(),
      traceId: input.traceId ?? randomUUID(),
      code,
    };

    await this.queue.enqueue(QUEUE_NAMES.OTP_SEND, job as unknown as Record<string, unknown>, {
      priority: 1,
      maxAttempts: job.maxAttempts,
      idempotencyKey,
    });

    return {
      challengeId,
      lineageId: resolution.lineageId,
      channel: input.channel.toLowerCase(),
      provider: resolution.primary.providerName,
      retryChannels: resolution.policy.retryChannels,
      resendCooldownSeconds: resolution.policy.resendCooldownSeconds,
    };
  }

  async retryOtp(input: {
    tenantId: string;
    challengeId: string;
    userId: string;
    recipient: string;
    channel: CommunicationChannel;
    purpose: CommunicationPurpose;
    tenantName?: string;
    traceId?: string;
  }) {
    return this.sendOtp(input);
  }

  async verifyOtp(input: {
    tenantId: string;
    userId: string;
    code: string;
    purpose: CommunicationPurpose;
    challengeId?: string;
  }) {
    await this.otp.verifyAndConsume(input.userId, input.code, toOtpPurpose(input.purpose));
    return {
      verified: true,
      tenantId: input.tenantId,
      challengeId: input.challengeId,
      replaySafe: true,
    };
  }

  async verifyProviderToken(input: {
    tenantId: string;
    provider: 'MSG91';
    accessToken: string;
    challengeId?: string;
  }) {
    return {
      verified: input.accessToken.length > 0,
      tenantId: input.tenantId,
      provider: input.provider,
      challengeId: input.challengeId,
      sessionAuthority: 'UICP',
    };
  }
}

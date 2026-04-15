import { Inject, Injectable, Optional } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { PasswordResetRequestCommand } from './password-reset-request.command';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { IIdentityRepository } from '../../ports/driven/i-identity.repository';
import { IEncryptionPort } from '../../ports/driven/i-encryption.port';
import { IQueuePort } from '../../ports/driven/i-queue.port';
import { ICachePort } from '../../ports/driven/i-cache.port';
import { IMetricsPort } from '../../ports/driven/i-metrics.port';
import { Email } from '../../../domain/value-objects/email.vo';
import { PhoneNumber } from '../../../domain/value-objects/phone-number.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { OtpDispatchPayload } from '../../contracts/otp-dispatch.contract';

@Injectable()
export class PasswordResetRequestHandler {
  constructor(
    @Inject(INJECTION_TOKENS.IDENTITY_REPOSITORY)
    private readonly identityRepo: IIdentityRepository,
    @Inject(INJECTION_TOKENS.ENCRYPTION_PORT)
    private readonly encryption: IEncryptionPort,
    @Inject(INJECTION_TOKENS.QUEUE_PORT)
    private readonly queue: IQueuePort,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {}

  async handle(cmd: PasswordResetRequestCommand): Promise<{ message: string }> {
    const tenantId = TenantId.from(cmd.tenantId);
    const identityType = cmd.identityType ?? (cmd.identity.includes('@') ? 'EMAIL' : 'PHONE');

    const normalized =
      identityType === 'EMAIL' ? Email.create(cmd.identity).getValue() : PhoneNumber.create(cmd.identity).getValue();
    const hash = await this.encryption.hmac(normalized, 'IDENTITY_VALUE');
    const identity = await this.identityRepo.findByHash(hash, identityType, tenantId);

    if (identity) {
      const resetToken = randomUUID();
      await this.cache.set(`password-reset:${cmd.tenantId}:${resetToken}`, identity.userId.toString(), 300);

      const payload: OtpDispatchPayload = {
        userId: identity.userId.toString(),
        tenantId: cmd.tenantId,
        recipient: normalized,
        channel: identityType === 'EMAIL' ? 'EMAIL' : 'SMS',
        purpose: 'PASSWORD_RESET',
        code: resetToken,
      };
      await this.queue.enqueue('otp-send', payload);
      this.metrics?.increment('uicp_otp_sent_total', {
        tenant_id: cmd.tenantId,
        channel: identityType === 'EMAIL' ? 'email' : 'sms',
        purpose: 'PASSWORD_RESET',
      });
    }

    return { message: 'If the identity exists, a reset OTP has been sent.' };
  }
}

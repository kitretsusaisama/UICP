import { Injectable, Inject, Optional } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { VerifyOtpCommand } from './verify-otp.command';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { IUserRepository } from '../../ports/driven/i-user.repository';
import { IEventStore } from '../../ports/driven/i-event-store';
import { IOutboxRepository, OutboxEvent } from '../../ports/driven/i-outbox.repository';
import { IMetricsPort } from '../../ports/driven/i-metrics.port';
import { OtpService } from '../../services/otp.service';
import { SessionService } from '../../services/session.service';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { IdentityId } from '../../../domain/value-objects/identity-id.vo';
import { SessionId } from '../../../domain/value-objects/session-id.vo';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';
import { RuntimeIdentityService } from '../../services/runtime-identity.service';

@Injectable()
export class VerifyOtpHandler {
  constructor(
    private readonly otpService: OtpService,
    @Inject(INJECTION_TOKENS.USER_REPOSITORY)
    private readonly userRepo: IUserRepository,
    @Inject(INJECTION_TOKENS.EVENT_STORE)
    private readonly eventStore: IEventStore,
    @Inject(INJECTION_TOKENS.OUTBOX_REPOSITORY)
    private readonly outboxRepo: IOutboxRepository,
    private readonly sessionService: SessionService,
    private readonly runtimeIdentityService: RuntimeIdentityService,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {}

  async handle(cmd: VerifyOtpCommand): Promise<{ verified: boolean; userStatus: string }> {
    // 1. Atomically verify and consume OTP
    try {
      await this.otpService.verifyAndConsume(cmd.userId, cmd.code, cmd.purpose);
    } catch (err) {
      const code = err instanceof DomainException ? err.errorCode : 'error';
      this.metrics?.increment('uicp_otp_verified_total', { tenant_id: cmd.tenantId, result: code === DomainErrorCode.OTP_ALREADY_USED ? 'reuse' : code === DomainErrorCode.OTP_EXPIRED ? 'expired' : 'invalid' });
      throw err;
    }

    // 2. Load user
    const userId = UserId.from(cmd.userId);
    const tenantId = TenantId.from(cmd.tenantId);
    const user = await this.userRepo.findById(userId, tenantId);
    if (!user) {
      throw new DomainException(DomainErrorCode.INVALID_CREDENTIALS, 'User not found');
    }

    // 3. Handle IDENTITY_VERIFICATION
    if (cmd.purpose === 'IDENTITY_VERIFICATION' && cmd.identityId) {
      user.verifyIdentity(IdentityId.from(cmd.identityId));
      const domainEvents = user.pullDomainEvents();
      await this.eventStore.append(cmd.userId, domainEvents);
      await this.userRepo.update(user);
    }

    await this.runtimeIdentityService.ensureForLegacyUser(user, 'member');

    // 4. Handle MFA
    if (cmd.purpose === 'MFA' && cmd.sessionId) {
      await this.sessionService.setStatus(
        SessionId.from(cmd.sessionId),
        tenantId,
        'ACTIVE',
      );
    }

    // 5. Insert outbox event
    const outboxEvent: OutboxEvent = {
      id: randomUUID(),
      eventType: 'OtpVerified',
      aggregateId: cmd.userId,
      aggregateType: 'User',
      tenantId: cmd.tenantId,
      payload: { userId: cmd.userId, purpose: cmd.purpose },
      status: 'PENDING',
      attempts: 0,
      createdAt: new Date(),
    };
    await this.outboxRepo.insertWithinTransaction(outboxEvent, null);

    this.metrics?.increment('uicp_otp_verified_total', { tenant_id: cmd.tenantId, result: 'success' });

    return { verified: true, userStatus: user.getStatus() };
  }
}

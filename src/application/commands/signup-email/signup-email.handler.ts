import { Injectable, Inject, ConflictException, Optional } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { SignupEmailCommand } from './signup-email.command';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { IUserRepository } from '../../ports/driven/i-user.repository';
import { IIdentityRepository } from '../../ports/driven/i-identity.repository';
import { IOutboxRepository, OutboxEvent } from '../../ports/driven/i-outbox.repository';
import { IEncryptionPort } from '../../ports/driven/i-encryption.port';
import { IQueuePort } from '../../ports/driven/i-queue.port';
import { ITracerPort } from '../../ports/driven/i-tracer.port';
import { IMetricsPort } from '../../ports/driven/i-metrics.port';
import { CredentialService } from '../../services/credential.service';
import { DistributedLockService } from '../../services/distributed-lock.service';
import { OtpService } from '../../services/otp.service';
import { RuntimeIdentityService } from '../../services/runtime-identity.service';
import { OtpDispatchPayload } from '../../contracts/otp-dispatch.contract';
import { Email } from '../../../domain/value-objects/email.vo';
import { RawPassword } from '../../../domain/value-objects/raw-password.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { User } from '../../../domain/aggregates/user.aggregate';
import { UicpLogger } from '../../../shared/logger/pino-logger.service';
import { measure } from '../../../shared/logger/measure';

@Injectable()
export class SignupEmailHandler {
  constructor(
    @Inject(INJECTION_TOKENS.USER_REPOSITORY)
    private readonly userRepo: IUserRepository,
    @Inject(INJECTION_TOKENS.IDENTITY_REPOSITORY)
    private readonly identityRepo: IIdentityRepository,
    @Inject(INJECTION_TOKENS.OUTBOX_REPOSITORY)
    private readonly outboxRepo: IOutboxRepository,
    @Inject(INJECTION_TOKENS.ENCRYPTION_PORT)
    private readonly encryption: IEncryptionPort,
    @Inject(INJECTION_TOKENS.QUEUE_PORT)
    private readonly queue: IQueuePort,
    private readonly credentialService: CredentialService,
    private readonly lockService: DistributedLockService,
    private readonly otpService: OtpService,
    private readonly runtimeIdentityService: RuntimeIdentityService,
    private readonly logger: UicpLogger,
    @Optional() @Inject(INJECTION_TOKENS.TRACER_PORT) private readonly tracer?: ITracerPort,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {}

  async handle(cmd: SignupEmailCommand): Promise<{ userId: string; message: string }> {
    return measure(
      { logger: this.logger, operation: 'signup', context: SignupEmailHandler.name },
      () => this.tracer?.withSpan(
        'signup_email_handler',
        () => this.doHandle(cmd),
        { 'service.name': 'uicp', 'tenant.id': cmd.tenantId },
      ) ?? this.doHandle(cmd),
    );
  }

  private async doHandle(cmd: SignupEmailCommand): Promise<{ userId: string; message: string }> {
    const email = Email.create(cmd.email);
    const rawPassword = RawPassword.create(cmd.password);
    const tenantId = TenantId.from(cmd.tenantId);

    const emailHash = await this.encryption.hmac(email.getValue(), 'IDENTITY_VALUE');
    const lockKey = DistributedLockService.identityLockKey(cmd.tenantId, emailHash);

    // WAR-GRADE DEFENSE: Phase 5 Temporal Consistency
    // The lock is now an optimization. DB unique constraints provide the true atomicity.
    return this.lockService.withLock(lockKey, 10000, async () => {
      // 1. Pre-check
      const existing = await this.identityRepo.findByHash(emailHash, 'EMAIL', tenantId);
      if (existing) {
        this.metrics?.increment('uicp_signup_total', { tenant_id: cmd.tenantId, result: 'conflict' });
        throw new ConflictException('IDENTITY_ALREADY_EXISTS');
      }

      const emailEnc = await this.encryption.encrypt(email.getValue(), 'IDENTITY_VALUE', tenantId);
      const user = User.createWithEmail({ email, tenantId, emailEnc, emailHash });
      const credential = await this.credentialService.hash(rawPassword);
      user.changePassword(credential);

      // 2. Perform DB save expecting ER_DUP_ENTRY ConflictException
      try {
        await this.userRepo.save(user);
      } catch (err: any) {
        if (err.name === 'ConflictException' || err.code === 'ER_DUP_ENTRY' || err.message?.includes('IDENTITY_ALREADY_EXISTS')) {
          this.metrics?.increment('uicp_signup_total', { tenant_id: cmd.tenantId, result: 'conflict' });
          throw new ConflictException('IDENTITY_ALREADY_EXISTS');
        }
        throw err;
      }

      await this.runtimeIdentityService.ensureForLegacyUser(user, 'member');

      const userId = user.getId().toString();
      const code = this.otpService.generate();
      await this.otpService.store(userId, 'IDENTITY_VERIFICATION', code);

      const otpPayload: OtpDispatchPayload = {
        userId,
        tenantId: cmd.tenantId,
        recipient: email.getValue(),
        code,
        channel: 'EMAIL',
        purpose: 'IDENTITY_VERIFICATION',
      };
      await this.queue.enqueue('otp-send', otpPayload);

      const outboxEvent: OutboxEvent = {
        id: randomUUID(),
        eventType: 'UserCreated',
        aggregateId: userId,
        aggregateType: 'User',
        tenantId: cmd.tenantId,
        payload: { userId, tenantId: cmd.tenantId },
        status: 'PENDING',
        attempts: 0,
        createdAt: new Date(),
      };
      await this.outboxRepo.insertWithinTransaction(outboxEvent, null);

      this.metrics?.increment('uicp_signup_total', { tenant_id: cmd.tenantId, result: 'success' });
      this.metrics?.increment('uicp_otp_sent_total', { tenant_id: cmd.tenantId, channel: 'email', purpose: 'IDENTITY_VERIFICATION' });

      return { userId, message: 'Verification OTP sent' };
    });
  }
}

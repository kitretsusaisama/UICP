import { Injectable, Inject } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { ChangePasswordCommand } from './change-password.command';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { IUserRepository } from '../../ports/driven/i-user.repository';
import { IOutboxRepository, OutboxEvent } from '../../ports/driven/i-outbox.repository';
import { ITokenRepository } from '../../ports/driven/i-token.repository';
import { CredentialService } from '../../services/credential.service';
import { SessionService } from '../../services/session.service';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { RawPassword } from '../../../domain/value-objects/raw-password.vo';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';

@Injectable()
export class ChangePasswordHandler {
  constructor(
    @Inject(INJECTION_TOKENS.USER_REPOSITORY)
    private readonly userRepo: IUserRepository,
    @Inject(INJECTION_TOKENS.OUTBOX_REPOSITORY)
    private readonly outboxRepo: IOutboxRepository,
    @Inject(INJECTION_TOKENS.TOKEN_REPOSITORY)
    private readonly tokenRepo: ITokenRepository,
    private readonly credentialService: CredentialService,
    private readonly sessionService: SessionService,
  ) {}

  async handle(cmd: ChangePasswordCommand): Promise<{ success: boolean }> {
    const userId = UserId.from(cmd.userId);
    const tenantId = TenantId.from(cmd.tenantId);

    // 1. Load user
    const user = await this.userRepo.findById(userId, tenantId);
    if (!user) {
      throw new DomainException(DomainErrorCode.INVALID_CREDENTIALS, 'User not found');
    }

    // 2. Validate current password format
    const currentRawPw = RawPassword.create(cmd.currentPassword);

    // 3. Verify current password
    const credential = user.getCredential();
    if (!credential) {
      throw new DomainException(DomainErrorCode.INVALID_CREDENTIALS, 'No credential found');
    }
    const valid = await this.credentialService.verify(currentRawPw, credential);
    if (!valid) {
      throw new DomainException(DomainErrorCode.INVALID_CREDENTIALS, 'Current password is incorrect');
    }

    // 4. Validate new password format
    const newRawPw = RawPassword.create(cmd.newPassword);

    // 5. Hash new password
    const newCredential = await this.credentialService.hash(newRawPw);

    // 6. Change password on aggregate
    user.changePassword(newCredential);

    // 7. Persist user
    await this.userRepo.update(user);

    // 8. Invalidate all sessions except current
    const sessions = await this.sessionService.listByUser(userId, tenantId);
    await Promise.all(
      sessions
        .filter((s) => s.id.toString() !== cmd.currentSessionId)
        .map((s) => this.sessionService.invalidate(s.id, tenantId)),
    );

    // 9. Revoke all token families
    await this.tokenRepo.revokeAllFamiliesByUser(userId, tenantId);

    // 10. Insert outbox event
    const outboxEvent: OutboxEvent = {
      id: randomUUID(),
      eventType: 'PasswordChanged',
      aggregateId: cmd.userId,
      aggregateType: 'User',
      tenantId: cmd.tenantId,
      payload: { userId: cmd.userId },
      status: 'PENDING',
      attempts: 0,
      createdAt: new Date(),
    };
    await this.outboxRepo.insertWithinTransaction(outboxEvent, null);

    return { success: true };
  }
}

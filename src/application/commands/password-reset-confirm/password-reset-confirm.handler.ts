import { Inject, Injectable } from '@nestjs/common';
import { PasswordResetConfirmCommand } from './password-reset-confirm.command';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { ICachePort } from '../../ports/driven/i-cache.port';
import { IUserRepository } from '../../ports/driven/i-user.repository';
import { CredentialService } from '../../services/credential.service';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { RawPassword } from '../../../domain/value-objects/raw-password.vo';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';

@Injectable()
export class PasswordResetConfirmHandler {
  constructor(
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
    @Inject(INJECTION_TOKENS.USER_REPOSITORY)
    private readonly userRepo: IUserRepository,
    private readonly credentialService: CredentialService,
  ) {}

  async handle(cmd: PasswordResetConfirmCommand): Promise<{ reset: boolean }> {
    const cacheKey = `password-reset:${cmd.tenantId}:${cmd.resetToken}`;
    const userId = await this.cache.get(cacheKey);
    if (!userId) {
      throw new DomainException(DomainErrorCode.INVALID_OTP, 'Invalid or expired password reset token');
    }

    const tenantId = TenantId.from(cmd.tenantId);
    const user = await this.userRepo.findById(UserId.from(userId), tenantId);
    if (!user) {
      throw new DomainException(DomainErrorCode.USER_NOT_FOUND, 'User not found');
    }

    const credential = await this.credentialService.hash(RawPassword.create(cmd.newPassword));
    user.changePassword(credential);
    await this.userRepo.update(user);
    await this.cache.del(cacheKey);

    return { reset: true };
  }
}

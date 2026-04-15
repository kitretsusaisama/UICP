import { Injectable, Inject } from '@nestjs/common';
import { GetUserQuery } from './get-user.query';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { IUserRepository } from '../../ports/driven/i-user.repository';
import { IEncryptionPort } from '../../ports/driven/i-encryption.port';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';

export interface UserProfileDto {
  id: string;
  tenantId: string;
  status: string;
  displayName?: string;
  identities: Array<{
    id: string;
    type: string;
    verified: boolean;
    verifiedAt?: string;
    createdAt: string;
  }>;
  createdAt: string;
  updatedAt: string;
}

/**
 * Query handler — load user profile with tenant isolation and PII decryption.
 *
 * Implements: Req 1.1 (tenant isolation), Req 1.3 (no cross-tenant rows),
 *             Req 13.1 (decrypt PII fields)
 */
@Injectable()
export class GetUserHandler {
  constructor(
    @Inject(INJECTION_TOKENS.USER_REPOSITORY)
    private readonly userRepo: IUserRepository,
    @Inject(INJECTION_TOKENS.ENCRYPTION_PORT)
    private readonly encryption: IEncryptionPort,
  ) {}

  async handle(query: GetUserQuery): Promise<UserProfileDto> {
    const userId = UserId.from(query.userId);
    const tenantId = TenantId.from(query.tenantId);

    // Load user — repository enforces WHERE tenant_id = ? (Req 1.1, 1.3)
    const user = await this.userRepo.findById(userId, tenantId);
    if (!user) {
      throw new DomainException(DomainErrorCode.USER_NOT_FOUND, `User ${query.userId} not found`);
    }

    // Decrypt PII fields (Req 13.1)
    let displayName: string | undefined;
    const identities = user.getIdentities();
    const decryptedIdentities = await Promise.all(
      identities.map(async (identity) => {
        return {
          id: identity.id.toString(),
          type: identity.getType(),
          verified: identity.isVerified(),
          verifiedAt: identity.getVerifiedAt()?.toISOString(),
          createdAt: identity.createdAt.toISOString(),
        };
      }),
    );

    return {
      id: user.getId().toString(),
      tenantId: user.getTenantId().toString(),
      status: user.getStatus(),
      displayName,
      identities: decryptedIdentities,
      createdAt: user.getCreatedAt().toISOString(),
      updatedAt: user.getUpdatedAt().toISOString(),
    };
  }
}

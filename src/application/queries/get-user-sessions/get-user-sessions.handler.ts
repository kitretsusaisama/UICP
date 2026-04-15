import { Injectable, Inject } from '@nestjs/common';
import { GetUserSessionsQuery } from './get-user-sessions.query';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { ISessionStore } from '../../ports/driven/i-session.store';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';

export interface SessionDto {
  id: string;
  status: string;
  browser: string;
  os: string;
  deviceType: string;
  deviceFingerprint?: string;
  ipHash: string;
  mfaVerified: boolean;
  mfaVerifiedAt?: string;
  createdAt: string;
  expiresAt: string;
  isActive: boolean;
}

/**
 * Query handler — list sessions from Redis, enriched with device info.
 *
 * Implements: Req 8.7 (list sessions with device type, browser, OS, IP hash,
 *             creation time, and MFA verification status)
 */
@Injectable()
export class GetUserSessionsHandler {
  constructor(
    @Inject(INJECTION_TOKENS.SESSION_STORE)
    private readonly sessionStore: ISessionStore,
  ) {}

  async handle(query: GetUserSessionsQuery): Promise<SessionDto[]> {
    const userId = UserId.from(query.userId);
    const tenantId = TenantId.from(query.tenantId);

    // Authorization: requesting user must be the owner (admin bypass handled at controller)
    if (query.requestingUserId !== query.userId) {
      throw new DomainException(
        DomainErrorCode.FORBIDDEN,
        'Cannot list sessions for another user',
      );
    }

    // Load sessions from Redis sorted set (Req 8.2)
    const sessions = await this.sessionStore.findByUserId(userId, tenantId);

    return sessions
      .filter((s) => !s.isExpired())
      .map((s) => ({
        id: s.id.toString(),
        status: s.getStatus(),
        browser: s.uaBrowser,
        os: s.uaOs,
        deviceType: s.uaDeviceType,
        deviceFingerprint: s.deviceFingerprint
          ? s.deviceFingerprint.substring(0, 8) + '...'
          : undefined,
        ipHash: s.ipHash,
        mfaVerified: s.isMfaVerified(),
        mfaVerifiedAt: s.getMfaVerifiedAt()?.toISOString(),
        createdAt: s.createdAt.toISOString(),
        expiresAt: s.getExpiresAt().toISOString(),
        isActive: s.isActive(),
      }));
  }
}

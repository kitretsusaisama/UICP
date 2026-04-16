import { Injectable, Inject, Optional } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { RefreshTokenCommand } from './refresh-token.command';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { ITokenRepository } from '../../ports/driven/i-token.repository';
import { IOutboxRepository, OutboxEvent } from '../../ports/driven/i-outbox.repository';
import { IUserRepository } from '../../ports/driven/i-user.repository';
import { ITracerPort } from '../../ports/driven/i-tracer.port';
import { IMetricsPort } from '../../ports/driven/i-metrics.port';
import { TokenService } from '../../services/token.service';
import { SessionService } from '../../services/session.service';
import { DistributedLockService } from '../../services/distributed-lock.service';
import { RuntimeIdentityService } from '../../services/runtime-identity.service';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { SessionId } from '../../../domain/value-objects/session-id.vo';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';

@Injectable()
export class RefreshTokenHandler {
  constructor(
    @Inject(INJECTION_TOKENS.TOKEN_REPOSITORY)
    private readonly tokenRepo: ITokenRepository,
    @Inject(INJECTION_TOKENS.OUTBOX_REPOSITORY)
    private readonly outboxRepo: IOutboxRepository,
    @Inject(INJECTION_TOKENS.USER_REPOSITORY)
    private readonly userRepo: IUserRepository,
    private readonly tokenService: TokenService,
    private readonly sessionService: SessionService,
    private readonly runtimeIdentityService: RuntimeIdentityService,
    private readonly lockService: DistributedLockService,
    @Optional() @Inject(INJECTION_TOKENS.TRACER_PORT) private readonly tracer?: ITracerPort,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {}

  async handle(cmd: RefreshTokenCommand): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    return this.tracer?.withSpan(
      'refresh_token_handler',
      () => this.doHandle(cmd),
      { 'service.name': 'uicp', 'tenant.id': cmd.tenantId },
    ) ?? this.doHandle(cmd);
  }

  private async doHandle(cmd: RefreshTokenCommand): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    // 1. Parse and verify refresh token
    const payload = this.tokenService.parseRefreshToken(cmd.refreshToken);
    const { jti, fid: familyId, sub: principalId, tid: tenantIdStr, sid: sessionId, mid: membershipIdFromToken } = payload as any;

    // 2. Check blocklist
    const blocklisted = await this.tokenRepo.isBlocklisted(jti);
    if (blocklisted) {
      throw new DomainException(DomainErrorCode.TOKEN_REVOKED, 'Token has been revoked');
    }

    const tenantId = TenantId.from(tenantIdStr ?? cmd.tenantId);
    const userIdVo = UserId.from(principalId);

    // 3-5. Acquire family lock and check for reuse
    const familyLockKey = DistributedLockService.tokenFamilyLockKey(familyId);
    return this.lockService.withLock(familyLockKey, 10000, async () => {
      // 4. Find refresh token record
      const record = await this.tokenRepo.findRefreshToken(jti, tenantId);
      if (!record) {
        throw new DomainException(DomainErrorCode.TOKEN_NOT_FOUND, 'Refresh token not found');
      }

      // 5. Reuse detection
      if (record.revoked) {
        await this.tokenRepo.revokeFamily(familyId, tenantId);
        await this.sessionService.invalidateAll(userIdVo, tenantId);

        // WAR-GRADE DEFENSE: Phase 7 SOC & Detection (Replay Attacks)
        // Refresh token reuse is a critical security event. A replay attack indicates
        // a token leak. We immediately emit an outbox event routed to the `soc-alert` queue
        // to alert SIEM and initiate account lockdown procedures.
        const reuseEvent: OutboxEvent = {
          id: randomUUID(),
          eventType: 'TokenReuseDetected', // OutboxRelayWorker routes this to soc-alert
          aggregateId: principalId,
          aggregateType: 'User',
          tenantId: tenantId.toString(),
          payload: { principalId, familyId, reuseJti: jti },
          status: 'PENDING',
          attempts: 0,
          createdAt: new Date(),
        };
        await this.outboxRepo.insertWithinTransaction(reuseEvent, null);

        this.metrics?.increment('uicp_token_refreshed_total', { tenant_id: cmd.tenantId, result: 'reuse_attack' });
        throw new DomainException(DomainErrorCode.REFRESH_TOKEN_REUSE, 'Refresh token reuse detected');
      }

      // 6. Revoke current token
      await this.tokenRepo.revokeToken(jti, tenantId);

      // 7. Load user
      const user = await this.userRepo.findById(userIdVo, tenantId);
      if (!user) {
        throw new DomainException(DomainErrorCode.INVALID_CREDENTIALS, 'User not found');
      }

      const runtimeIdentity = await this.runtimeIdentityService.ensureForLegacyUser(user, 'member');

      // 8. Load session
      let session = sessionId
        ? await this.sessionService.findById(SessionId.from(sessionId), tenantId)
        : null;

      if (!session) {
        // Create minimal session stub for token minting
        session = await this.sessionService.createSession({
          tenantId,
          userId: userIdVo,
          principalId: runtimeIdentity.principalId,
          membershipId: membershipIdFromToken ?? runtimeIdentity.membershipId,
          actorId: runtimeIdentity.actorId,
          policyVersion: 'legacy-policy-v1',
          manifestVersion: 'legacy-manifest-v1',
          ipHash: 'unknown',
          userAgent: 'unknown',
        });
      }

      // 9. Mint new tokens with same family ID
      const capabilities = [
        'identity.session.read',
        'identity.session.revoke',
        'tenant.actor.switch',
        'policy.read',
        'policy.simulate',
        'policy.explain',
      ];
      const { token: accessToken } = await this.tokenService.mintAccessToken({
        principalId: runtimeIdentity.principalId,
        tenantId: runtimeIdentity.tenantId,
        membershipId: membershipIdFromToken ?? runtimeIdentity.membershipId,
        actorId: runtimeIdentity.actorId,
        session,
        capabilities,
        roles: ['member'],
        perms: capabilities,
        amr: ['pwd'],
        policyVersion: 'legacy-policy-v1',
        manifestVersion: 'legacy-manifest-v1',
      });
      const { token: refreshToken, jti: newJti, expiresAt: newExpiresAt } = await
        await this.tokenService.mintRefreshToken(
          userIdVo,
          tenantId,
          familyId,
          membershipIdFromToken ?? runtimeIdentity.membershipId,
          session.id.toString(),
        );

      this.metrics?.increment('uicp_token_minted_total', { tenant_id: cmd.tenantId, type: 'access' });
      this.metrics?.increment('uicp_token_minted_total', { tenant_id: cmd.tenantId, type: 'refresh' });

      // 10. Save new refresh token
      await this.tokenRepo.saveRefreshToken({
        jti: newJti,
        familyId,
        userId: principalId,
        tenantId: tenantId.toString(),
        revoked: false,
        expiresAt: newExpiresAt,
        createdAt: new Date(),
      });

      // 11. Insert outbox event
      const refreshedEvent: OutboxEvent = {
        id: randomUUID(),
        eventType: 'TokenRefreshed',
        aggregateId: principalId,
        aggregateType: 'User',
        tenantId: tenantId.toString(),
        payload: { principalId, oldJti: jti, newJti, familyId },
        status: 'PENDING',
        attempts: 0,
        createdAt: new Date(),
      };
      await this.outboxRepo.insertWithinTransaction(refreshedEvent, null);

      this.metrics?.increment('uicp_token_refreshed_total', { tenant_id: cmd.tenantId, result: 'success' });

      return { accessToken, refreshToken, expiresIn: 900 };
    });
  }
}

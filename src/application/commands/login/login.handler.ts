import { Injectable, Inject, Optional } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { LoginCommand } from './login.command';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { IUserRepository } from '../../ports/driven/i-user.repository';
import { IIdentityRepository } from '../../ports/driven/i-identity.repository';
import { IOutboxRepository, OutboxEvent } from '../../ports/driven/i-outbox.repository';
import { ITokenRepository } from '../../ports/driven/i-token.repository';
import { IEncryptionPort } from '../../ports/driven/i-encryption.port';
import { ITracerPort } from '../../ports/driven/i-tracer.port';
import { IMetricsPort } from '../../ports/driven/i-metrics.port';
import { CredentialService } from '../../services/credential.service';
import { SessionService } from '../../services/session.service';
import { TokenService } from '../../services/token.service';
import { DistributedLockService } from '../../services/distributed-lock.service';
import { RuntimeIdentityService } from '../../services/runtime-identity.service';
import { RawPassword } from '../../../domain/value-objects/raw-password.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';
import { UicpLogger } from '../../../shared/logger/pino-logger.service';
import { measure } from '../../../shared/logger/measure';

@Injectable()
export class LoginHandler {
  constructor(
    @Inject(INJECTION_TOKENS.USER_REPOSITORY)
    private readonly userRepo: IUserRepository,
    @Inject(INJECTION_TOKENS.IDENTITY_REPOSITORY)
    private readonly identityRepo: IIdentityRepository,
    @Inject(INJECTION_TOKENS.OUTBOX_REPOSITORY)
    private readonly outboxRepo: IOutboxRepository,
    @Inject(INJECTION_TOKENS.TOKEN_REPOSITORY)
    private readonly tokenRepo: ITokenRepository,
    @Inject(INJECTION_TOKENS.ENCRYPTION_PORT)
    private readonly encryption: IEncryptionPort,
    private readonly credentialService: CredentialService,
    private readonly sessionService: SessionService,
    private readonly tokenService: TokenService,
    private readonly runtimeIdentityService: RuntimeIdentityService,
    private readonly lockService: DistributedLockService,
    private readonly logger: UicpLogger,
    @Optional() @Inject(INJECTION_TOKENS.TRACER_PORT) private readonly tracer?: ITracerPort,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {}

  async handle(cmd: LoginCommand): Promise<{
    accessToken: string;
    refreshToken: string;
    sessionId: string;
    expiresIn: number;
  }> {
    return measure(
      { logger: this.logger, operation: 'login', context: LoginHandler.name, extra: { ipHash: cmd.ipHash } },
      () => this.tracer?.withSpan(
        'login_handler',
        () => this.doHandle(cmd),
        { 'service.name': 'uicp', 'tenant.id': cmd.tenantId },
      ) ?? this.doHandle(cmd),
    );
  }

  private async doHandle(cmd: LoginCommand): Promise<{
    accessToken: string;
    refreshToken: string;
    sessionId: string;
    expiresIn: number;
  }> {
    // 1. Detect identity type
    const identityType = cmd.identityType ?? (cmd.identity.includes('@') ? 'EMAIL' : 'PHONE');
    const tenantId = TenantId.from(cmd.tenantId);

    // 2. Compute HMAC
    const identityHash = await this.encryption.hmac(cmd.identity, 'IDENTITY_VALUE');

    // 3. Find identity — timing-safe: dummy verify if not found
    const identity = await this.identityRepo.findByHash(identityHash, identityType, tenantId);
    if (!identity) {
      await this.credentialService.dummyVerify();
      throw new DomainException(DomainErrorCode.INVALID_CREDENTIALS, 'Invalid credentials');
    }

    // 4. Load user
    const userId = UserId.from(identity.userId.toString());
    const user = await this.userRepo.findById(userId, tenantId);
    if (!user) {
      await this.credentialService.dummyVerify();
      throw new DomainException(DomainErrorCode.INVALID_CREDENTIALS, 'Invalid credentials');
    }

    // 5. UEBA scoring stub
    const _ueba = { score: 0.0, signals: [] };

    // 6. Auth policy eval
    const status = user.getStatus();
    if (status === 'DELETED') {
      this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: cmd.tenantId, result: 'failed' });
      throw new DomainException(DomainErrorCode.ACCOUNT_DELETED, 'Account has been deleted');
    }
    if (status === 'SUSPENDED' && user.isSuspendedNow()) {
      this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: cmd.tenantId, result: 'failed' });
      throw new DomainException(DomainErrorCode.ACCOUNT_SUSPENDED, 'Account is suspended');
    }
    if (status === 'PENDING') {
      this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: cmd.tenantId, result: 'failed' });
      throw new DomainException(DomainErrorCode.ACCOUNT_NOT_ACTIVATED, 'Account is not activated');
    }

    // 7. Verify credential
    const rawPassword = RawPassword.create(cmd.password);
    const credential = user.getCredential();
    if (!credential) {
      this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: cmd.tenantId, result: 'failed' });
      throw new DomainException(DomainErrorCode.INVALID_CREDENTIALS, 'Invalid credentials');
    }
    const valid = await this.credentialService.verify(rawPassword, credential);
    if (!valid) {
      this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: cmd.tenantId, result: 'failed' });
      throw new DomainException(DomainErrorCode.INVALID_CREDENTIALS, 'Invalid credentials');
    }

    // 8. MFA check stub
    const requireMfa = false;
    if (requireMfa) {
      this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: cmd.tenantId, result: 'mfa_required' });
    }

    const runtimeIdentity = await this.runtimeIdentityService.ensureForLegacyUser(user, 'member');

    // 9-10. Acquire session lock and create session
    const sessionLockKey = DistributedLockService.sessionCreationLockKey(cmd.tenantId, userId.toString());
    const session = await this.lockService.withLock(sessionLockKey, 5000, async () => {
      return this.sessionService.createSession({
        tenantId,
        userId,
        principalId: runtimeIdentity.principalId,
        membershipId: runtimeIdentity.membershipId,
        actorId: runtimeIdentity.actorId,
        policyVersion: 'legacy-policy-v1',
        manifestVersion: 'legacy-manifest-v1',
        ipHash: cmd.ipHash,
        userAgent: cmd.userAgent,
        deviceFingerprint: cmd.deviceFingerprint,
        requireMfa,
      });
    });

    // 11. Mint tokens
    const familyId = randomUUID();
    const defaultCapabilities = [
      'identity.session.read',
      'identity.session.revoke',
      'tenant.actor.switch',
      'policy.read',
      'policy.simulate',
      'policy.explain',
    ];
    const { token: accessToken, jti: accessJti } = this.tokenService.mintAccessToken({
      principalId: runtimeIdentity.principalId,
      tenantId: runtimeIdentity.tenantId,
      membershipId: runtimeIdentity.membershipId,
      actorId: runtimeIdentity.actorId,
      session,
      capabilities: defaultCapabilities,
      roles: ['member'],
      perms: defaultCapabilities,
      amr: ['pwd'],
      policyVersion: 'legacy-policy-v1',
      manifestVersion: 'legacy-manifest-v1',
    });
    const { token: refreshToken, jti: refreshJti, expiresAt: refreshExpiresAt } =
      this.tokenService.mintRefreshToken(userId, tenantId, familyId, runtimeIdentity.membershipId, session.id.toString());

    this.metrics?.increment('uicp_token_minted_total', { tenant_id: cmd.tenantId, type: 'access' });
    this.metrics?.increment('uicp_token_minted_total', { tenant_id: cmd.tenantId, type: 'refresh' });

    // 12. Save refresh token
    await this.tokenRepo.saveRefreshToken({
      jti: refreshJti,
      familyId,
      userId: userId.toString(),
      tenantId: cmd.tenantId,
      revoked: false,
      expiresAt: refreshExpiresAt,
      createdAt: new Date(),
    });

    // 13. Insert outbox events
    const now = new Date();
    const loginEvent: OutboxEvent = {
      id: randomUUID(),
      eventType: 'LoginSucceeded',
      aggregateId: userId.toString(),
      aggregateType: 'User',
      tenantId: cmd.tenantId,
      payload: {
        userId: userId.toString(),
        sessionId: session.id.toString(),
        mfaRequired: requireMfa,
        threatScore: 0.0,
      },
      status: 'PENDING',
      attempts: 0,
      createdAt: now,
    };
    const sessionEvent: OutboxEvent = {
      id: randomUUID(),
      eventType: 'SessionCreated',
      aggregateId: session.id.toString(),
      aggregateType: 'Session',
      tenantId: cmd.tenantId,
      payload: {
        sessionId: session.id.toString(),
        userId: userId.toString(),
        ipHash: cmd.ipHash,
      },
      status: 'PENDING',
      attempts: 0,
      createdAt: now,
    };
    await this.outboxRepo.insertWithinTransaction(loginEvent, null);
    await this.outboxRepo.insertWithinTransaction(sessionEvent, null);

    // 14. Async rehash if needed
    if (this.credentialService.needsRehash(credential)) {
      setImmediate(() => this.credentialService.rehash(rawPassword));
    }

    this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: cmd.tenantId, result: requireMfa ? 'mfa_required' : 'success' });

    return {
      accessToken,
      refreshToken,
      sessionId: session.id.toString(),
      expiresIn: 900,
    };
  }
}

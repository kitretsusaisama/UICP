import { Injectable, Inject } from '@nestjs/common';
import { randomUUID, timingSafeEqual } from 'crypto';
import { OAuthCallbackCommand, OAuthProvider } from './oauth-callback.command';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { IIdentityRepository } from '../../ports/driven/i-identity.repository';
import { IUserRepository } from '../../ports/driven/i-user.repository';
import { IOutboxRepository, OutboxEvent } from '../../ports/driven/i-outbox.repository';
import { ITokenRepository } from '../../ports/driven/i-token.repository';
import { IEncryptionPort } from '../../ports/driven/i-encryption.port';
import { SessionService } from '../../services/session.service';
import { TokenService } from '../../services/token.service';
import { RuntimeIdentityService } from '../../services/runtime-identity.service';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { IdentityId } from '../../../domain/value-objects/identity-id.vo';
import { User } from '../../../domain/aggregates/user.aggregate';
import { Identity, IdentityType, toEncryptedValue } from '../../../domain/entities/identity.entity';
import { Email } from '../../../domain/value-objects/email.vo';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';

const PROVIDER_IDENTITY_TYPE: Record<OAuthProvider, IdentityType> = {
  google: 'OAUTH_GOOGLE',
  github: 'OAUTH_GITHUB',
  apple: 'OAUTH_APPLE',
  microsoft: 'OAUTH_MICROSOFT',
};

@Injectable()
export class OAuthCallbackHandler {
  constructor(
    @Inject(INJECTION_TOKENS.IDENTITY_REPOSITORY)
    private readonly identityRepo: IIdentityRepository,
    @Inject(INJECTION_TOKENS.USER_REPOSITORY)
    private readonly userRepo: IUserRepository,
    @Inject(INJECTION_TOKENS.OUTBOX_REPOSITORY)
    private readonly outboxRepo: IOutboxRepository,
    @Inject(INJECTION_TOKENS.TOKEN_REPOSITORY)
    private readonly tokenRepo: ITokenRepository,
    @Inject(INJECTION_TOKENS.ENCRYPTION_PORT)
    private readonly encryption: IEncryptionPort,
    private readonly sessionService: SessionService,
    private readonly tokenService: TokenService,
    private readonly runtimeIdentityService: RuntimeIdentityService,
  ) {}

  async handle(cmd: OAuthCallbackCommand): Promise<{
    accessToken: string;
    refreshToken: string;
    sessionId: string;
    isNewUser: boolean;
  }> {
    // 1. Verify state (timing-safe)
    const stateA = Buffer.from(cmd.state);
    const stateB = Buffer.from(cmd.expectedState);
    if (stateA.length !== stateB.length || !timingSafeEqual(stateA, stateB)) {
      throw new DomainException(DomainErrorCode.INVALID_OAUTH_STATE, 'Invalid OAuth state parameter');
    }

    // 2. Map provider to identity type
    const identityType = PROVIDER_IDENTITY_TYPE[cmd.provider];
    const tenantId = TenantId.from(cmd.tenantId);

    // 3. Use providerSub as the identity value
    const providerSub = cmd.providerSub;

    // 4. Compute HMAC of providerSub for lookup
    const subHash = await this.encryption.hmac(providerSub, 'IDENTITY_VALUE');

    // 5. Look up existing identity
    const existingIdentity = await this.identityRepo.findByProviderSub(providerSub, identityType, tenantId);

    let user: User;
    let isNewUser = false;

    if (existingIdentity) {
      // 6. Existing identity — load user
      const loadedUser = await this.userRepo.findById(existingIdentity.userId, tenantId);
      if (!loadedUser) {
        throw new DomainException(DomainErrorCode.INVALID_CREDENTIALS, 'User not found');
      }
      user = loadedUser;
    } else {
      // 7. New identity — create user
      isNewUser = true;

      if (cmd.providerEmail) {
        const email = Email.create(cmd.providerEmail);
        const emailEnc = await this.encryption.encrypt(email.getValue(), 'IDENTITY_VALUE', tenantId);
        const emailHash = await this.encryption.hmac(email.getValue(), 'IDENTITY_VALUE');
        user = User.createWithEmail({ email, tenantId, emailEnc, emailHash });
      } else {
        // No email — create with stub email VO using providerSub as placeholder
        const subEnc = await this.encryption.encrypt(providerSub, 'IDENTITY_VALUE', tenantId);
        // Build a minimal user via reconstitute for OAuth-only accounts
        const userId = (await import('../../../domain/value-objects/user-id.vo')).UserId.create();
        user = User.reconstitute({
          id: userId,
          tenantId,
          status: 'ACTIVE',
          identities: [],
          version: 0,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      }

      // Link OAuth identity (pre-verified)
      const oauthIdentity = Identity.createOAuth({
        id: IdentityId.create(),
        tenantId,
        userId: user.getId(),
        type: identityType,
        valueEnc: toEncryptedValue(providerSub),
        valueHash: subHash,
        providerSub,
        verified: true,
      });
      user.linkIdentity(oauthIdentity);
      await this.userRepo.save(user);
    }

    // 8. Create session and mint tokens
    const session = await this.sessionService.createSession({
      tenantId,
      userId: user.getId(),
      principalId: user.getId().toString(),
      ipHash: cmd.ipHash,
      userAgent: cmd.userAgent,
    });

    const runtimeIdentity = await this.runtimeIdentityService.ensureForLegacyUser(user, 'member');
    const familyId = randomUUID();
    const { token: accessToken } = await this.tokenService.mintAccessToken({
      principalId: runtimeIdentity.principalId,
      tenantId: runtimeIdentity.tenantId,
      membershipId: runtimeIdentity.membershipId,
      actorId: runtimeIdentity.actorId,
      session,
      capabilities: ['identity.session.read', 'identity.session.revoke', 'tenant.actor.switch'],
      roles: ['member'],
      perms: ['identity.session.read', 'identity.session.revoke', 'tenant.actor.switch'],
      amr: ['oauth'],
      policyVersion: 'legacy-policy-v1',
      manifestVersion: 'legacy-manifest-v1',
    });
    const { token: refreshToken, jti: refreshJti, expiresAt: refreshExpiresAt } = await
      await this.tokenService.mintRefreshToken(user.getId(), tenantId, familyId, runtimeIdentity.membershipId, session.id.toString());

    // Save refresh token
    await this.tokenRepo.saveRefreshToken({
      jti: refreshJti,
      familyId,
      userId: user.getId().toString(),
      tenantId: cmd.tenantId,
      revoked: false,
      expiresAt: refreshExpiresAt,
      createdAt: new Date(),
    });

    // 9. Insert outbox events
    const loginEvent: OutboxEvent = {
      id: randomUUID(),
      eventType: 'LoginSucceeded',
      aggregateId: user.getId().toString(),
      aggregateType: 'User',
      tenantId: cmd.tenantId,
      payload: {
        userId: user.getId().toString(),
        sessionId: session.id.toString(),
        provider: cmd.provider,
        isNewUser,
      },
      status: 'PENDING',
      attempts: 0,
      createdAt: new Date(),
    };
    await this.outboxRepo.insertWithinTransaction(loginEvent, null);

    return {
      accessToken,
      refreshToken,
      sessionId: session.id.toString(),
      isNewUser,
    };
  }
}

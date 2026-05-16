import { Injectable, Inject, Logger, Optional } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { UserId } from '../../domain/value-objects/user-id.vo';
import { AuthSession, AuthState, AuthStep, ProfileRequirement } from '../../domain/auth-session';
import { User } from '../../domain/aggregates/user.aggregate';
import { DomainErrorCode } from '../../domain/exceptions/domain-error-codes';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { IUserRepository } from '../ports/driven/i-user.repository';
import { IIdentityRepository } from '../ports/driven/i-identity.repository';
import { IEncryptionPort } from '../ports/driven/i-encryption.port';
import { ICachePort } from '../ports/driven/i-cache.port';
import { IMetricsPort } from '../ports/driven/i-metrics.port';
import { CredentialService } from './credential.service';
import { SessionService } from './session.service';
import { TokenService } from './token.service';
import { AuthSessionService } from './auth-session.service';
import { RuntimeIdentityService } from './runtime-identity.service';

export type AuthMethod = 'password' | 'otp' | 'magic_link' | 'oauth';

export interface AuthAttemptRequest {
  tenantId: string;
  identity: string;
  authMethod: AuthMethod;
  secret?: string;
  stateToken?: string;
  deviceFingerprint?: string;
  ipHash?: string;
  userAgent?: string;
}

export type AuthAttemptResponse =
  | { state: 'authenticated'; accessToken: string; refreshToken: string; sessionId: string }
  | { state: 'challenge_required'; challengeType: string; sessionId: string; stateToken: string; expiresAt: string }
  | { state: 'challenge_passed'; sessionId: string; stateToken: string }
  | { state: 'profile_required'; sessionId: string; stateToken: string; requiredFields: ProfileRequirement[] }
  | { state: 'identity_not_found'; autoCreate: boolean; sessionId: string; stateToken: string }
  | { state: 'resumed'; sessionId: string; stateToken: string; currentStep: AuthStep; completedSteps: AuthStep[] }
  | { state: 'resumed_challenge'; sessionId: string; stateToken: string; challengeType: string; expiresAt: string }
  | { state: 'resumed_profile_required'; sessionId: string; stateToken: string; requiredFields: ProfileRequirement[] }
  | { state: 'blocked'; reason: string }
  | { state: 'error'; message: string };

@Injectable()
export class UnifiedAuthService {
  private readonly logger = new Logger(UnifiedAuthService.name);

  constructor(
    @Inject(INJECTION_TOKENS.USER_REPOSITORY)
    private readonly userRepo: IUserRepository,
    @Inject(INJECTION_TOKENS.IDENTITY_REPOSITORY)
    private readonly identityRepo: IIdentityRepository,
    @Inject(INJECTION_TOKENS.ENCRYPTION_PORT)
    private readonly encryption: IEncryptionPort,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
    private readonly credentialService: CredentialService,
    private readonly sessionService: SessionService,
    private readonly tokenService: TokenService,
    private readonly authSessionService: AuthSessionService,
    private readonly runtimeIdentityService: RuntimeIdentityService,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {}

  async authenticate(request: AuthAttemptRequest): Promise<AuthAttemptResponse> {
    try {
      if (request.stateToken) {
        return await this.handleResumption(request);
      }
      return await this.handleNewAttempt(request);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error({ error: message, tenantId: request.tenantId }, 'Auth attempt failed');
      return { state: 'error', message };
    }
  }

  private async handleNewAttempt(request: AuthAttemptRequest): Promise<AuthAttemptResponse> {
    const tenantId = TenantId.from(request.tenantId);

    const { session, stateToken } = await this.authSessionService.createSession({
      tenantId: request.tenantId,
      deviceFingerprint: request.deviceFingerprint,
      ipHash: request.ipHash,
      userAgent: request.userAgent,
    });

    const identityType = request.identity.includes('@') ? 'EMAIL' : 'PHONE';
    const identityHash = await this.encryption.hmac(request.identity, 'IDENTITY_VALUE');
    const identity = await this.identityRepo.findByHash(identityHash, identityType, tenantId);

    if (!identity) {
      const idType = identityType ?? 'EMAIL';
      session.submitIdentity(request.identity ?? '', idType);
      await this.authSessionService.updateSession(session);

      return {
        state: 'identity_not_found',
        autoCreate: true,
        sessionId: session.id,
        stateToken,
      };
    }

    const userId = identity?.userId ? UserId.from(identity.userId.toString()) : UserId.create();
    const user = await this.userRepo.findById(userId, tenantId);

    if (!user) {
      await this.credentialService.dummyVerify();
      return { state: 'error', message: 'User not found' };
    }

    const status = user.getStatus();
    if (status === 'DELETED') {
      this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: request.tenantId, result: 'failed' });
      return { state: 'blocked', reason: 'Account has been deleted' };
    }

    if (status === 'SUSPENDED' && user.isSuspendedNow()) {
      this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: request.tenantId, result: 'failed' });
      return { state: 'blocked', reason: 'Account is suspended' };
    }

    if (status === 'PENDING') {
      this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: request.tenantId, result: 'failed' });
      return { state: 'blocked', reason: 'Account is not activated' };
    }

    if (request.authMethod === 'password' && request.secret) {
      const credential = user.getCredential();
      if (!credential) {
        return { state: 'error', message: 'No password set' };
      }

      const { RawPassword } = await import('../../domain/value-objects/raw-password.vo');
      const rawPassword = RawPassword.create(request.secret);
      const valid = await this.credentialService.verify(rawPassword, credential);

      if (!valid) {
        this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: request.tenantId, result: 'failed' });
        return { state: 'error', message: 'Invalid credentials' };
      }
    }

    session.submitIdentity(request.identity, identityType, userId);
    await this.authSessionService.updateSession(session);

    return await this.createAuthenticatedSession(session, user, request, stateToken);
  }

  private async handleResumption(request: AuthAttemptRequest): Promise<AuthAttemptResponse> {
    const stateToken = request.stateToken ?? '';
    if (!this.authSessionService.isValidStateTokenFormat(stateToken)) {
      return { state: 'error', message: 'Invalid state token' };
    }

    const { session, canResume, contextDiff } = await this.authSessionService.resumeSession({
      stateToken,
      currentDeviceFingerprint: request.deviceFingerprint,
      currentIpHash: request.ipHash,
      currentUserAgent: request.userAgent,
    });

    if (!canResume || !session) {
      return { state: 'error', message: 'Session expired or not found' };
    }

    if (contextDiff?.deviceChanged || contextDiff?.ipChanged) {
      this.logger.warn({ contextDiff }, 'Significant context change in resumed session');
    }

    const currentState = session.getState();
    const sessionStateToken = this.generateStateToken(session);

    if (currentState === AuthState.CHALLENGED && request.secret) {
      session.passChallenge();
      await this.authSessionService.updateSession(session);

      if (session.getState() === AuthState.PROFILE_REQUIRED) {
        return {
          state: 'resumed_profile_required',
          sessionId: session.id,
          stateToken: sessionStateToken,
          requiredFields: session.getProfileRequired(),
        };
      }

      const tenantId = TenantId.from(request.tenantId);
      const userId = session.getUserId();
      if (!userId) return { state: 'error', message: 'No user ID in session' };

      const user = await this.userRepo.findById(userId, tenantId);
      if (!user) return { state: 'error', message: 'User not found' };

      return await this.createAuthenticatedSession(session, user, request, sessionStateToken);
    }

    if (currentState === AuthState.CHALLENGED) {
      return {
        state: 'resumed_challenge',
        sessionId: session.id,
        stateToken: sessionStateToken,
        challengeType: session.getChallengeType() ?? 'otp',
        expiresAt: session.getChallengeExpiresAt()?.toISOString() ?? '',
      };
    }

    if (currentState === AuthState.PROFILE_REQUIRED) {
      return {
        state: 'resumed_profile_required',
        sessionId: session.id,
        stateToken,
        requiredFields: session.getProfileRequired(),
      };
    }

    if (currentState === AuthState.IDENTITY_PENDING) {
      return {
        state: 'identity_not_found',
        autoCreate: true,
        sessionId: session.id,
        stateToken,
      };
    }

    return {
      state: 'resumed',
      sessionId: session.id,
      stateToken,
      currentStep: session.getCurrentStep(),
      completedSteps: session.getCompletedSteps(),
    };
  }

  async completeProfile(stateToken: string, profileData: Record<string, string>): Promise<AuthAttemptResponse> {
    const { sessionId, tenantId } = this.parseStateToken(stateToken);
    const tenantIdVo = TenantId.from(tenantId);

    const session = await this.authSessionService.getSession(tenantId, sessionId);
    if (!session || session.getState() !== AuthState.PROFILE_REQUIRED) {
      return { state: 'error', message: 'Invalid session state for profile completion' };
    }

    session.completeProfile();
    await this.authSessionService.updateSession(session);

    const userId = session.getUserId();
    if (!userId) return { state: 'error', message: 'No user ID in session' };

    const user = await this.userRepo.findById(userId, tenantIdVo);
    if (!user) return { state: 'error', message: 'User not found' };

    const newStateToken = this.generateStateToken(session);
    return await this.createAuthenticatedSession(session, user, { tenantId, identity: '', authMethod: 'password' }, newStateToken);
  }

  private async createAuthenticatedSession(
    authSession: AuthSession,
    user: User,
    request: AuthAttemptRequest,
    stateToken: string,
  ): Promise<AuthAttemptResponse> {
    const tenantId = TenantId.from(request.tenantId);

    authSession.passChallenge();
    await this.authSessionService.updateSession(authSession);

    const userSession = await this.sessionService.createSession({
      tenantId,
      userId: user.getId(),
      principalId: user.getId().toString(),
      ipHash: request.ipHash ?? '',
      userAgent: request.userAgent ?? '',
      deviceFingerprint: request.deviceFingerprint,
    });

    const runtimeIdentity = await this.runtimeIdentityService.ensureForLegacyUser(user, 'member');

    const familyId = randomUUID();
    const { token: accessToken } = await this.tokenService.mintAccessToken({
      principalId: runtimeIdentity.principalId,
      tenantId: request.tenantId,
      membershipId: runtimeIdentity.membershipId,
      actorId: runtimeIdentity.actorId,
      session: userSession,
      capabilities: ['identity.session.read', 'identity.session.revoke'],
      amr: ['pwd'],
    });

    const { token: refreshToken } = await this.tokenService.mintRefreshToken(
      user.getId(),
      tenantId,
      familyId,
      runtimeIdentity.membershipId,
      userSession.id.toString(),
    );

    await this.cache.set(`token-family:${familyId}`, JSON.stringify({ validJtis: [] }), 604800);

    this.metrics?.increment('uicp_auth_attempts_total', { tenant_id: request.tenantId, result: 'success' });

    return {
      state: 'authenticated',
      accessToken,
      refreshToken,
      sessionId: userSession.id.toString(),
    };
  }

  private generateStateToken(session: AuthSession): string {
    return Buffer.from(JSON.stringify({
      sid: session.id,
      tid: session.tenantId.toString(),
      exp: session.getExpiresAt().getTime(),
    })).toString('base64');
  }

  private parseStateToken(token: string): { sessionId: string; tenantId: string } {
    const payload = JSON.parse(Buffer.from(token, 'base64').toString());
    return { sessionId: payload.sid, tenantId: payload.tid };
  }
}
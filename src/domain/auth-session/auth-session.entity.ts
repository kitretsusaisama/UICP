import { randomUUID } from 'crypto';
import { TenantId } from '../value-objects/tenant-id.vo';
import { UserId } from '../value-objects/user-id.vo';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';
import { AuthState, isTerminalState, canContinue } from './auth-state.enum';
import { AuthStep } from './auth-step.enum';
import { AuthContext } from './auth-context.entity';

/**
 * Challenge types for MFA
 */
export type ChallengeType = 'otp_email' | 'otp_sms' | 'webauthn' | 'captcha' | 'passphrase';

/**
 * Profile fields that might be required
 */
export interface ProfileRequirement {
  field: string;
  required: boolean;
  validation?: {
    minLength?: number;
    maxLength?: number;
    pattern?: string;
  };
}

/**
 * Auth Session - manages the unified auth flow
 *
 * This is separate from the user Session (which represents an authenticated session)
 * This tracks the multi-step authentication process itself
 */
export class AuthSession {
  readonly id: string;
  readonly tenantId: TenantId;
  private _state: AuthState;
  private _currentStep: AuthStep;
  private _completedSteps: AuthStep[];
  private _userId?: UserId;
  private _identityHint?: string;
  private _identityType?: string;
  private _challengeType?: ChallengeType;
  private _challengeAttempts: number;
  private _challengeExpiresAt?: Date;
  private _profileRequired: ProfileRequirement[];
  private _originalContext: AuthContext;
  private _createdAt: Date;
  private _expiresAt: Date;

  private constructor(params: {
    id: string;
    tenantId: TenantId;
    state: AuthState;
    currentStep: AuthStep;
    completedSteps: AuthStep[];
    userId?: UserId;
    identityHint?: string;
    identityType?: string;
    challengeType?: ChallengeType;
    challengeAttempts: number;
    challengeExpiresAt?: Date;
    profileRequired: ProfileRequirement[];
    originalContext: AuthContext;
    createdAt: Date;
    expiresAt: Date;
  }) {
    this.id = params.id;
    this.tenantId = params.tenantId;
    this._state = params.state;
    this._currentStep = params.currentStep;
    this._completedSteps = params.completedSteps;
    this._userId = params.userId;
    this._identityHint = params.identityHint;
    this._identityType = params.identityType;
    this._challengeType = params.challengeType;
    this._challengeAttempts = params.challengeAttempts;
    this._challengeExpiresAt = params.challengeExpiresAt;
    this._profileRequired = params.profileRequired;
    this._originalContext = params.originalContext;
    this._createdAt = params.createdAt;
    this._expiresAt = params.expiresAt;
  }

  static create(params: {
    tenantId: TenantId;
    context: AuthContext;
    ttlSeconds?: number;
  }): AuthSession {
    const now = new Date();
    const ttl = params.ttlSeconds ?? 3600;

    return new AuthSession({
      id: randomUUID(),
      tenantId: params.tenantId,
      state: AuthState.STARTED,
      currentStep: AuthStep.INIT,
      completedSteps: [],
      challengeAttempts: 0,
      profileRequired: [],
      originalContext: params.context,
      createdAt: now,
      expiresAt: new Date(now.getTime() + ttl * 1000),
    });
  }

  static reconstitute(params: {
    id: string;
    tenantId: TenantId;
    state: AuthState;
    currentStep: AuthStep;
    completedSteps: AuthStep[];
    userId?: UserId;
    identityHint?: string;
    identityType?: string;
    challengeType?: ChallengeType;
    challengeAttempts: number;
    challengeExpiresAt?: Date;
    profileRequired: ProfileRequirement[];
    originalContext: AuthContext;
    createdAt: Date;
    expiresAt: Date;
  }): AuthSession {
    return new AuthSession(params);
  }

  submitIdentity(identity: string, identityType: string, userId?: UserId): void {
    if (!canContinue(this._state)) {
      throw new DomainException(
        DomainErrorCode.INVALID_AUTH_STATE,
        `Cannot submit identity in state ${this._state}`,
      );
    }

    this._identityHint = identity;
    this._identityType = identityType;
    this._userId = userId;
    this._currentStep = AuthStep.IDENTITY;
    this._completedSteps.push(AuthStep.IDENTITY);

    if (userId) {
      this._state = AuthState.IDENTITY_VERIFIED;
      this._currentStep = AuthStep.IDENTITY_VERIFIED;
      this._completedSteps.push(AuthStep.IDENTITY_VERIFIED);
    } else {
      this._state = AuthState.IDENTITY_PENDING;
      this._currentStep = AuthStep.IDENTITY_VERIFICATION;
    }
  }

  verifyIdentity(userId: UserId): void {
    if (this._state !== AuthState.IDENTITY_PENDING) {
      throw new DomainException(
        DomainErrorCode.INVALID_AUTH_STATE,
        `Cannot verify identity in state ${this._state}`,
      );
    }

    this._userId = userId;
    this._state = AuthState.IDENTITY_VERIFIED;
    this._currentStep = AuthStep.IDENTITY_VERIFIED;
    this._completedSteps.push(AuthStep.IDENTITY_VERIFIED);
  }

  requireChallenge(challengeType: ChallengeType, expiresInSeconds: number = 300): void {
    if (this._state !== AuthState.IDENTITY_VERIFIED) {
      throw new DomainException(
        DomainErrorCode.INVALID_AUTH_STATE,
        `Cannot require challenge in state ${this._state}`,
      );
    }

    this._challengeType = challengeType;
    this._challengeAttempts = 0;
    this._challengeExpiresAt = new Date(Date.now() + expiresInSeconds * 1000);
    this._state = AuthState.CHALLENGED;
    this._currentStep = AuthStep.CHALLENGE;
    this._completedSteps.push(AuthStep.CHALLENGE);
  }

  passChallenge(profileRequired: ProfileRequirement[] = []): void {
    if (this._state !== AuthState.CHALLENGED) {
      throw new DomainException(
        DomainErrorCode.INVALID_AUTH_STATE,
        `Cannot pass challenge in state ${this._state}`,
      );
    }

    this._challengeType = undefined;
    this._challengeExpiresAt = undefined;
    this._completedSteps.push(AuthStep.CHALLENGE_PASSED);

    if (profileRequired.length > 0) {
      this._profileRequired = profileRequired;
      this._state = AuthState.PROFILE_REQUIRED;
      this._currentStep = AuthStep.PROFILE;
    } else {
      this._state = AuthState.AUTHENTICATED;
      this._currentStep = AuthStep.COMPLETE;
      this._completedSteps.push(AuthStep.COMPLETE);
    }
  }

  failChallenge(maxAttempts: number = 3): void {
    if (this._state !== AuthState.CHALLENGED) {
      throw new DomainException(
        DomainErrorCode.INVALID_AUTH_STATE,
        `Cannot fail challenge in state ${this._state}`,
      );
    }

    this._challengeAttempts++;

    if (this._challengeAttempts >= maxAttempts) {
      this._state = AuthState.BLOCKED;
      throw new DomainException(
        DomainErrorCode.AUTH_CHALLENGE_EXHAUSTED,
        'Maximum challenge attempts exceeded',
      );
    }
  }

  completeProfile(): void {
    if (this._state !== AuthState.PROFILE_REQUIRED) {
      throw new DomainException(
        DomainErrorCode.INVALID_AUTH_STATE,
        `Cannot complete profile in state ${this._state}`,
      );
    }

    this._profileRequired = [];
    this._state = AuthState.AUTHENTICATED;
    this._currentStep = AuthStep.COMPLETE;
    this._completedSteps.push(AuthStep.PROFILE_COMPLETE);
    this._completedSteps.push(AuthStep.COMPLETE);
  }

  block(): void {
    if (isTerminalState(this._state)) {
      throw new DomainException(
        DomainErrorCode.INVALID_AUTH_STATE,
        `Cannot block in terminal state ${this._state}`,
      );
    }
    this._state = AuthState.BLOCKED;
  }

  abandon(): void {
    if (isTerminalState(this._state)) return;
    this._state = AuthState.ABANDONED;
  }

  extendTtl(seconds: number): void {
    this._expiresAt = new Date(Date.now() + seconds * 1000);
  }

  getState(): AuthState { return this._state; }
  getCurrentStep(): AuthStep { return this._currentStep; }
  getCompletedSteps(): AuthStep[] { return [...this._completedSteps]; }
  getUserId(): UserId | undefined { return this._userId; }
  getIdentityHint(): string | undefined { return this._identityHint; }
  getIdentityType(): string | undefined { return this._identityType; }
  getChallengeType(): ChallengeType | undefined { return this._challengeType; }
  getChallengeAttempts(): number { return this._challengeAttempts; }
  getChallengeExpiresAt(): Date | undefined { return this._challengeExpiresAt; }
  getProfileRequired(): ProfileRequirement[] { return [...this._profileRequired]; }
  getOriginalContext(): AuthContext { return this._originalContext; }
  getCreatedAt(): Date { return this._createdAt; }
  getExpiresAt(): Date { return this._expiresAt; }

  isExpired(): boolean { return new Date() > this._expiresAt; }
  isAuthenticated(): boolean { return this._state === AuthState.AUTHENTICATED; }
  canResume(): boolean { return canContinue(this._state) && !this.isExpired(); }

  toRedisHash(): Record<string, string> {
    return {
      id: this.id,
      tenantId: this.tenantId.toString(),
      state: this._state,
      currentStep: this._currentStep,
      completedSteps: JSON.stringify(this._completedSteps),
      userId: this._userId?.toString() ?? '',
      identityHint: this._identityHint ?? '',
      identityType: this._identityType ?? '',
      challengeType: this._challengeType ?? '',
      challengeAttempts: String(this._challengeAttempts),
      challengeExpiresAt: this._challengeExpiresAt?.toISOString() ?? '',
      profileRequired: JSON.stringify(this._profileRequired),
      originalContext: JSON.stringify(this._originalContext),
      createdAt: this._createdAt.toISOString(),
      expiresAt: this._expiresAt.toISOString(),
    };
  }

  static fromRedisHash(hash: Record<string, string | undefined>): AuthSession {
    const id = hash.id ?? '';
    const tenantId = hash.tenantId ?? '';
    const state = hash.state ?? 'STARTED';
    const currentStep = hash.currentStep ?? 'INIT';
    const completedSteps = hash.completedSteps ?? '[]';
    const userId = hash.userId ?? '';
    const identityHint = hash.identityHint ?? '';
    const identityType = hash.identityType ?? '';
    const challengeType = hash.challengeType ?? '';
    const challengeAttempts = hash.challengeAttempts ?? '0';
    const challengeExpiresAt = hash.challengeExpiresAt ?? '';
    const profileRequired = hash.profileRequired ?? '[]';
    const originalContext = hash.originalContext ?? '{}';
    const createdAt = hash.createdAt ?? new Date().toISOString();
    const expiresAt = hash.expiresAt ?? new Date().toISOString();

    return AuthSession.reconstitute({
      id,
      tenantId: TenantId.from(tenantId),
      state: state as AuthState,
      currentStep: currentStep as AuthStep,
      completedSteps: JSON.parse(completedSteps),
      userId: userId ? UserId.from(userId) : undefined,
      identityHint: identityHint || undefined,
      identityType: identityType || undefined,
      challengeType: (challengeType || '') as ChallengeType || undefined,
      challengeAttempts: parseInt(challengeAttempts, 10),
      challengeExpiresAt: challengeExpiresAt ? new Date(challengeExpiresAt) : undefined,
      profileRequired: JSON.parse(profileRequired),
      originalContext: JSON.parse(originalContext),
      createdAt: new Date(createdAt),
      expiresAt: new Date(expiresAt),
    });
  }
}
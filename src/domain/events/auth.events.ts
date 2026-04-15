import { DomainEvent } from './domain-event.base';

// ── OTP purpose and channel enums ──────────────────────────────────────────

export type OtpPurpose = 'IDENTITY_VERIFICATION' | 'MFA' | 'PASSWORD_RESET';
export type OtpChannel = 'EMAIL' | 'SMS';

// ── Kill chain stage enum ──────────────────────────────────────────────────

export type KillChainStage =
  | 'RECONNAISSANCE'
  | 'INITIAL_ACCESS'
  | 'CREDENTIAL_ACCESS'
  | 'LATERAL_MOVEMENT'
  | 'ACCOUNT_TAKEOVER';

export interface SignalResult {
  signal: string;
  score: number;
  detail?: string;
}

// ── Auth Events ────────────────────────────────────────────────────────────

export class LoginSucceededEvent extends DomainEvent {
  readonly eventType = 'LoginSucceeded' as const;
  constructor(
    public readonly payload: {
      userId: string;
      sessionId: string;
      mfaRequired: boolean;
      threatScore: number;
    },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.userId, aggregateType: 'User', aggregateSeq, tenantId });
  }
}

export class LoginFailedEvent extends DomainEvent {
  readonly eventType = 'LoginFailed' as const;
  constructor(
    public readonly payload: {
      identityHash: string;
      reason: string;
      ipHash: string;
      threatScore: number;
    },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.identityHash, aggregateType: 'Identity', aggregateSeq, tenantId });
  }
}

export class TokenRefreshedEvent extends DomainEvent {
  readonly eventType = 'TokenRefreshed' as const;
  constructor(
    public readonly payload: {
      userId: string;
      oldJti: string;
      newJti: string;
      familyId: string;
    },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.userId, aggregateType: 'User', aggregateSeq, tenantId });
  }
}

export class TokenReuseDetectedEvent extends DomainEvent {
  readonly eventType = 'TokenReuseDetected' as const;
  constructor(
    public readonly payload: {
      userId: string;
      familyId: string;
      reuseJti: string;
      revokedCount: number;
    },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.userId, aggregateType: 'User', aggregateSeq, tenantId });
  }
}

export class OtpVerifiedEvent extends DomainEvent {
  readonly eventType = 'OtpVerified' as const;
  constructor(
    public readonly payload: {
      userId: string;
      purpose: OtpPurpose;
      channel: OtpChannel;
    },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({ aggregateId: payload.userId, aggregateType: 'User', aggregateSeq, tenantId });
  }
}

export class ThreatDetectedEvent extends DomainEvent {
  readonly eventType = 'ThreatDetected' as const;
  constructor(
    public readonly payload: {
      userId?: string;
      ipHash: string;
      threatScore: number;
      killChainStage: KillChainStage;
      signals: SignalResult[];
      responseActions: string[];
    },
    tenantId: string,
    aggregateSeq: number,
  ) {
    super({
      aggregateId: payload.userId ?? payload.ipHash,
      aggregateType: 'ThreatEvent',
      aggregateSeq,
      tenantId,
    });
  }
}

export type AuthDomainEvent =
  | LoginSucceededEvent
  | LoginFailedEvent
  | TokenRefreshedEvent
  | TokenReuseDetectedEvent
  | OtpVerifiedEvent
  | ThreatDetectedEvent;

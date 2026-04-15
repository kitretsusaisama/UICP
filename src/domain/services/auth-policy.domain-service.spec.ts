import { User } from '../aggregates/user.aggregate';
import { TenantId } from '../value-objects/tenant-id.vo';
import { toEncryptedValue } from '../entities/identity.entity';
import { DomainErrorCode } from '../exceptions/domain-error-codes';
import { AuthPolicyDomainService, TenantPolicy } from './auth-policy.domain-service';

// ── Helpers ────────────────────────────────────────────────────────────────

function buildActiveUser(): User {
  const tenantId = TenantId.create();
  const user = User.createWithEmail({
    email: {
      getValue: () => 'test@example.com',
      getDomain: () => 'example.com',
      toHmacInput: () => 'test@example.com',
      toString: () => 'test@example.com',
    } as any,
    tenantId,
    emailEnc: toEncryptedValue('enc-value'),
    emailHash: 'hash-value',
  });
  const identity = user.getIdentities()[0]!;
  user.verifyIdentity(identity.id);
  return user;
}

function buildPendingUser(): User {
  const tenantId = TenantId.create();
  return User.createWithEmail({
    email: {
      getValue: () => 'test@example.com',
      getDomain: () => 'example.com',
      toHmacInput: () => 'test@example.com',
      toString: () => 'test@example.com',
    } as any,
    tenantId,
    emailEnc: toEncryptedValue('enc-value'),
    emailHash: 'hash-value',
  });
}

const noMfaPolicy: TenantPolicy = { mfaPolicy: 'none' };

// ── Tests ──────────────────────────────────────────────────────────────────

describe('AuthPolicyDomainService', () => {
  let service: AuthPolicyDomainService;

  beforeEach(() => {
    service = new AuthPolicyDomainService();
  });

  // ── Status checks ──────────────────────────────────────────────────────────

  describe('DELETED user', () => {
    it('returns DENY(ACCOUNT_DELETED)', () => {
      const user = buildActiveUser();
      user.delete();

      const result = service.evaluate({ user, tenantPolicy: noMfaPolicy, threatScore: 0, deviceTrusted: false });

      expect(result.decision).toBe('DENY');
      if (result.decision === 'DENY') {
        expect(result.reason).toBe(DomainErrorCode.ACCOUNT_DELETED);
      }
    });
  });

  describe('SUSPENDED user', () => {
    it('returns DENY(ACCOUNT_SUSPENDED) with retryAfter when suspendUntil is in the future', () => {
      const user = buildActiveUser();
      const futureDate = new Date(Date.now() + 60_000);
      user.suspend('policy violation', futureDate);

      const result = service.evaluate({ user, tenantPolicy: noMfaPolicy, threatScore: 0, deviceTrusted: false });

      expect(result.decision).toBe('DENY');
      if (result.decision === 'DENY') {
        expect(result.reason).toBe(DomainErrorCode.ACCOUNT_SUSPENDED);
        expect(result.retryAfter).toEqual(futureDate);
      }
    });

    it('returns DENY(ACCOUNT_SUSPENDED) with no retryAfter for indefinite suspension', () => {
      const user = buildActiveUser();
      user.suspend('policy violation'); // no until → indefinite

      const result = service.evaluate({ user, tenantPolicy: noMfaPolicy, threatScore: 0, deviceTrusted: false });

      expect(result.decision).toBe('DENY');
      if (result.decision === 'DENY') {
        expect(result.reason).toBe(DomainErrorCode.ACCOUNT_SUSPENDED);
        expect(result.retryAfter).toBeUndefined();
      }
    });
  });

  describe('PENDING user', () => {
    it('returns DENY(ACCOUNT_NOT_ACTIVATED)', () => {
      const user = buildPendingUser();

      const result = service.evaluate({ user, tenantPolicy: noMfaPolicy, threatScore: 0, deviceTrusted: false });

      expect(result.decision).toBe('DENY');
      if (result.decision === 'DENY') {
        expect(result.reason).toBe(DomainErrorCode.ACCOUNT_NOT_ACTIVATED);
      }
    });
  });

  // ── MFA policy checks ──────────────────────────────────────────────────────

  describe('MFA policy: required', () => {
    const requiredPolicy: TenantPolicy = { mfaPolicy: 'required' };

    it('returns REQUIRE_MFA when threatScore is 0.0', () => {
      const user = buildActiveUser();
      const result = service.evaluate({ user, tenantPolicy: requiredPolicy, threatScore: 0.0, deviceTrusted: false });
      expect(result.decision).toBe('REQUIRE_MFA');
    });

    it('returns REQUIRE_MFA when threatScore is 1.0', () => {
      const user = buildActiveUser();
      const result = service.evaluate({ user, tenantPolicy: requiredPolicy, threatScore: 1.0, deviceTrusted: false });
      expect(result.decision).toBe('REQUIRE_MFA');
    });
  });

  describe('MFA policy: adaptive (default threshold 0.35)', () => {
    const adaptivePolicy: TenantPolicy = { mfaPolicy: 'adaptive' };

    it('returns REQUIRE_MFA when threatScore is 0.36 (above threshold)', () => {
      const user = buildActiveUser();
      const result = service.evaluate({ user, tenantPolicy: adaptivePolicy, threatScore: 0.36, deviceTrusted: false });
      expect(result.decision).toBe('REQUIRE_MFA');
    });

    it('returns ALLOW when threatScore is exactly 0.35 (threshold is exclusive)', () => {
      const user = buildActiveUser();
      const result = service.evaluate({ user, tenantPolicy: adaptivePolicy, threatScore: 0.35, deviceTrusted: false });
      expect(result.decision).toBe('ALLOW');
    });

    it('returns ALLOW when threatScore is 0.0', () => {
      const user = buildActiveUser();
      const result = service.evaluate({ user, tenantPolicy: adaptivePolicy, threatScore: 0.0, deviceTrusted: false });
      expect(result.decision).toBe('ALLOW');
    });
  });

  describe('MFA policy: adaptive with custom threshold', () => {
    const customPolicy: TenantPolicy = { mfaPolicy: 'adaptive', adaptiveMfaThreshold: 0.7 };

    it('returns REQUIRE_MFA when threatScore 0.71 exceeds custom threshold 0.7', () => {
      const user = buildActiveUser();
      const result = service.evaluate({ user, tenantPolicy: customPolicy, threatScore: 0.71, deviceTrusted: false });
      expect(result.decision).toBe('REQUIRE_MFA');
    });

    it('returns ALLOW when threatScore is exactly 0.70 (not exceeded)', () => {
      const user = buildActiveUser();
      const result = service.evaluate({ user, tenantPolicy: customPolicy, threatScore: 0.70, deviceTrusted: false });
      expect(result.decision).toBe('ALLOW');
    });
  });

  describe('MFA policy: none', () => {
    it('returns ALLOW even when threatScore is 1.0', () => {
      const user = buildActiveUser();
      const result = service.evaluate({ user, tenantPolicy: noMfaPolicy, threatScore: 1.0, deviceTrusted: false });
      expect(result.decision).toBe('ALLOW');
    });
  });

  // ── Happy path ─────────────────────────────────────────────────────────────

  describe('all checks pass', () => {
    it('returns ALLOW for ACTIVE user with mfaPolicy none and threatScore 0.0', () => {
      const user = buildActiveUser();
      const result = service.evaluate({ user, tenantPolicy: noMfaPolicy, threatScore: 0.0, deviceTrusted: false });
      expect(result.decision).toBe('ALLOW');
    });
  });
});

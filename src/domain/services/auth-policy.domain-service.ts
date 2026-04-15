import { User } from '../aggregates/user.aggregate';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

// ── Types ──────────────────────────────────────────────────────────────────

export type MfaPolicy = 'none' | 'adaptive' | 'required';

export interface TenantPolicy {
  mfaPolicy: MfaPolicy;
  /** Threat score threshold above which adaptive MFA is triggered (default: 0.35). */
  adaptiveMfaThreshold?: number;
}

export type AuthDenyReason =
  | typeof DomainErrorCode.ACCOUNT_DELETED
  | typeof DomainErrorCode.ACCOUNT_SUSPENDED
  | typeof DomainErrorCode.ACCOUNT_NOT_ACTIVATED;

export type AuthPolicyDecision =
  | { decision: 'ALLOW' }
  | { decision: 'REQUIRE_MFA' }
  | { decision: 'DENY'; reason: AuthDenyReason; retryAfter?: Date };

export interface AuthPolicyParams {
  user: User;
  tenantPolicy: TenantPolicy;
  threatScore: number;
  deviceTrusted: boolean;
}

// ── Service ────────────────────────────────────────────────────────────────

/**
 * AuthPolicyDomainService — pure domain service with no infrastructure dependencies.
 *
 * Implements the 6-step check chain:
 *   1. DELETED  → DENY(ACCOUNT_DELETED)
 *   2. SUSPENDED + suspendUntil > now() → DENY(ACCOUNT_SUSPENDED, retryAfter)
 *   3. PENDING  → DENY(ACCOUNT_NOT_ACTIVATED)
 *   4. MFA policy 'required' → REQUIRE_MFA
 *   5. MFA policy 'adaptive' + threatScore > threshold → REQUIRE_MFA
 *   6. All checks pass → ALLOW
 */
export class AuthPolicyDomainService {
  evaluate(params: AuthPolicyParams): AuthPolicyDecision {
    const { user, tenantPolicy, threatScore } = params;
    const status = user.getStatus();

    // Step 1: Deleted accounts are permanently denied
    if (status === 'DELETED') {
      return {
        decision: 'DENY',
        reason: DomainErrorCode.ACCOUNT_DELETED,
      };
    }

    // Step 2: Suspended accounts — check if suspension is still active
    if (status === 'SUSPENDED') {
      const suspendUntil = user.getSuspendUntil();
      // Indefinite suspension or future suspension end date
      if (!suspendUntil || suspendUntil > new Date()) {
        return {
          decision: 'DENY',
          reason: DomainErrorCode.ACCOUNT_SUSPENDED,
          retryAfter: suspendUntil,
        };
      }
      // Suspension has elapsed — fall through (treat as effectively active)
    }

    // Step 3: Pending accounts have not verified an identity yet
    if (status === 'PENDING') {
      return {
        decision: 'DENY',
        reason: DomainErrorCode.ACCOUNT_NOT_ACTIVATED,
      };
    }

    // Step 4: Tenant requires MFA for all logins
    if (tenantPolicy.mfaPolicy === 'required') {
      return { decision: 'REQUIRE_MFA' };
    }

    // Step 5: Adaptive MFA — trigger when threat score exceeds threshold
    if (tenantPolicy.mfaPolicy === 'adaptive') {
      const threshold = tenantPolicy.adaptiveMfaThreshold ?? 0.35;
      if (threatScore > threshold) {
        return { decision: 'REQUIRE_MFA' };
      }
    }

    // Step 6: All checks passed
    return { decision: 'ALLOW' };
  }
}

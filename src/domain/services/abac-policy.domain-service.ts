import { AbacCondition, EvaluationContext } from '../value-objects/abac-condition.vo';
import { TenantId } from '../value-objects/tenant-id.vo';

// ── Types ──────────────────────────────────────────────────────────────────

export type PolicyEffect = 'ALLOW' | 'DENY';
export type AbacDecision = 'ALLOW' | 'DENY';

/**
 * An ABAC policy as understood by the domain service.
 * Infrastructure layers map their persistence model to this interface.
 */
export interface AbacPolicy {
  readonly id: string;
  readonly tenantId: TenantId;
  readonly name: string;
  readonly effect: PolicyEffect;
  /** Higher priority policies are evaluated first. */
  readonly priority: number;
  readonly subjectCondition: AbacCondition;
  readonly resourceCondition: AbacCondition;
  readonly actionCondition: AbacCondition;
}

export interface AbacEvaluationContext {
  subject: Record<string, unknown>;
  resource: Record<string, unknown>;
  action: Record<string, unknown>;
  env: Record<string, unknown>;
}

export interface AbacEvaluationResult {
  decision: AbacDecision;
  /** The policy that produced the final decision, if any matched. */
  matchedPolicyId?: string;
  matchedPolicyName?: string;
}

// ── Service ────────────────────────────────────────────────────────────────

/**
 * AbacPolicyDomainService — pure domain service implementing the deny-override algorithm.
 *
 * Evaluation algorithm (Section 3.6):
 *   1. Sort policies by priority DESC
 *   2. For each policy, evaluate subject + resource + action conditions
 *   3. If all three match and effect=DENY → return DENY immediately (deny override)
 *   4. If all three match and effect=ALLOW → record as potential ALLOW
 *   5. If any ALLOW recorded and no DENY → return ALLOW
 *   6. Default → DENY (implicit deny)
 */
export class AbacPolicyDomainService {
  evaluate(policies: AbacPolicy[], context: AbacEvaluationContext): AbacEvaluationResult {
    // Build the evaluation context expected by AbacCondition
    const evalCtx: EvaluationContext = {
      subject: context.subject,
      resource: context.resource,
      env: { ...context.env, action: context.action },
    };

    // Sort by priority descending — higher priority evaluated first
    const sorted = [...policies].sort((a, b) => b.priority - a.priority);

    let firstAllow: AbacPolicy | undefined;

    for (const policy of sorted) {
      const subjectMatch = policy.subjectCondition.evaluate(evalCtx);
      if (!subjectMatch) continue;

      // Build resource-specific context for resource condition
      const resourceCtx: EvaluationContext = {
        subject: context.subject,
        resource: context.resource,
        env: evalCtx.env,
      };
      const resourceMatch = policy.resourceCondition.evaluate(resourceCtx);
      if (!resourceMatch) continue;

      // Build action-specific context for action condition
      const actionCtx: EvaluationContext = {
        subject: context.subject,
        resource: context.action,
        env: evalCtx.env,
      };
      const actionMatch = policy.actionCondition.evaluate(actionCtx);
      if (!actionMatch) continue;

      // All three conditions matched
      if (policy.effect === 'DENY') {
        // Deny override — return immediately
        return {
          decision: 'DENY',
          matchedPolicyId: policy.id,
          matchedPolicyName: policy.name,
        };
      }

      // Record first ALLOW match (highest priority wins)
      if (!firstAllow) {
        firstAllow = policy;
      }
    }

    if (firstAllow) {
      return {
        decision: 'ALLOW',
        matchedPolicyId: firstAllow.id,
        matchedPolicyName: firstAllow.name,
      };
    }

    // Implicit deny — no policy matched
    return { decision: 'DENY' };
  }
}

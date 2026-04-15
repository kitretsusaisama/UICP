import * as fc from 'fast-check';
import { AbacPolicyDomainService, AbacPolicy, AbacEvaluationContext } from './abac-policy.domain-service';
import { AbacCondition } from '../value-objects/abac-condition.vo';
import { TenantId } from '../value-objects/tenant-id.vo';

// ── Helpers ────────────────────────────────────────────────────────────────

const TENANT_ID = TenantId.from('a1b2c3d4-e5f6-4789-8abc-def012345678');

/** A condition that always evaluates to true for any context. */
const ALWAYS_TRUE = AbacCondition.parse('subject.role == "any" OR NOT subject.role == "any"');

/** A condition that always evaluates to false for any context. */
const ALWAYS_FALSE = AbacCondition.parse('subject.role == "__never_matches__"');

/** Build a policy that always matches (all three conditions are always-true). */
function buildMatchingPolicy(
  id: string,
  effect: 'ALLOW' | 'DENY',
  priority: number,
): AbacPolicy {
  return {
    id,
    tenantId: TENANT_ID,
    name: `policy-${id}`,
    effect,
    priority,
    subjectCondition: ALWAYS_TRUE,
    resourceCondition: ALWAYS_TRUE,
    actionCondition: ALWAYS_TRUE,
  };
}

/** Build a policy that never matches (subject condition is always-false). */
function buildNonMatchingPolicy(
  id: string,
  effect: 'ALLOW' | 'DENY',
  priority: number,
): AbacPolicy {
  return {
    id,
    tenantId: TENANT_ID,
    name: `policy-${id}`,
    effect,
    priority,
    subjectCondition: ALWAYS_FALSE,
    resourceCondition: ALWAYS_TRUE,
    actionCondition: ALWAYS_TRUE,
  };
}

/** A minimal evaluation context — values don't matter since conditions are always-true/false. */
const EVAL_CTX: AbacEvaluationContext = {
  subject: { role: 'user', tenantId: 'tenant-a' },
  resource: { type: 'document', id: 'doc-1' },
  action: { name: 'read' },
  env: { time: '12:00' },
};

// ── Arbitraries ────────────────────────────────────────────────────────────

/** Generates a unique policy ID string. */
const policyIdArb = fc.uuid();

/** Generates a priority in a reasonable range. */
const priorityArb = fc.integer({ min: -100, max: 100 });

/** Generates a matching ALLOW policy. */
const matchingAllowArb = fc
  .tuple(policyIdArb, priorityArb)
  .map(([id, priority]) => buildMatchingPolicy(id, 'ALLOW', priority));

/** Generates a matching DENY policy. */
const matchingDenyArb = fc
  .tuple(policyIdArb, priorityArb)
  .map(([id, priority]) => buildMatchingPolicy(id, 'DENY', priority));

/** Generates a non-matching policy (either effect — it won't fire). */
const nonMatchingArb = fc
  .tuple(policyIdArb, priorityArb, fc.constantFrom<'ALLOW' | 'DENY'>('ALLOW', 'DENY'))
  .map(([id, priority, effect]) => buildNonMatchingPolicy(id, effect, priority));

// ── Property Tests ─────────────────────────────────────────────────────────

/**
 * Property 11: Any matching DENY policy overrides all ALLOW policies regardless of priority
 *
 * **Validates: Req 9.3**
 *
 * For any policy set containing at least one matching DENY policy (regardless of
 * how many matching ALLOW policies exist or what their priorities are), the
 * evaluation result MUST always be DENY.
 */
describe('AbacPolicyDomainService — Property 11: deny-override', () => {
  let service: AbacPolicyDomainService;

  beforeEach(() => {
    service = new AbacPolicyDomainService();
  });

  it('DENY always wins over any number of matching ALLOW policies regardless of priority', () => {
    /**
     * **Validates: Req 9.3**
     *
     * Generate:
     *   - 0..5 matching ALLOW policies (all will match the context)
     *   - 1..3 matching DENY policies (all will match the context)
     *   - 0..3 non-matching policies of either effect (should not affect outcome)
     *
     * Shuffle the combined list to ensure evaluation order doesn't matter.
     * Assert: decision is always DENY.
     */
    fc.assert(
      fc.property(
        fc.array(matchingAllowArb, { minLength: 0, maxLength: 5 }),
        fc.array(matchingDenyArb, { minLength: 1, maxLength: 3 }),
        fc.array(nonMatchingArb, { minLength: 0, maxLength: 3 }),
        fc.integer({ min: 0 }), // seed for shuffle
        (allowPolicies, denyPolicies, nonMatchingPolicies, shuffleSeed) => {
          const combined = [...allowPolicies, ...denyPolicies, ...nonMatchingPolicies];

          // Deterministic shuffle using the seed so fast-check can reproduce failures
          const shuffled = [...combined].sort((a, b) => {
            const hashA = (a.id.charCodeAt(0) + shuffleSeed) % combined.length;
            const hashB = (b.id.charCodeAt(0) + shuffleSeed) % combined.length;
            return hashA - hashB;
          });

          const result = service.evaluate(shuffled, EVAL_CTX);

          expect(result.decision).toBe('DENY');
        },
      ),
    );
  });

  it('DENY wins even when the DENY policy has the lowest priority', () => {
    /**
     * **Validates: Req 9.3**
     *
     * Specifically tests that priority ordering does not allow a low-priority DENY
     * to be skipped in favour of high-priority ALLOWs.
     */
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 1, max: 100 }), { minLength: 1, maxLength: 5 }),
        (allowPriorities) => {
          const allowPolicies = allowPriorities.map((p, i) =>
            buildMatchingPolicy(`allow-${i}`, 'ALLOW', p),
          );

          // DENY has the lowest possible priority
          const denyPolicy = buildMatchingPolicy('deny-low-priority', 'DENY', -9999);

          const policies = [...allowPolicies, denyPolicy];
          const result = service.evaluate(policies, EVAL_CTX);

          expect(result.decision).toBe('DENY');
        },
      ),
    );
  });

  it('DENY wins even when the DENY policy has the highest priority', () => {
    /**
     * **Validates: Req 9.3**
     */
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: -100, max: 99 }), { minLength: 1, maxLength: 5 }),
        (allowPriorities) => {
          const allowPolicies = allowPriorities.map((p, i) =>
            buildMatchingPolicy(`allow-${i}`, 'ALLOW', p),
          );

          const denyPolicy = buildMatchingPolicy('deny-high-priority', 'DENY', 9999);

          const policies = [...allowPolicies, denyPolicy];
          const result = service.evaluate(policies, EVAL_CTX);

          expect(result.decision).toBe('DENY');
        },
      ),
    );
  });

  // ── Complementary unit tests ───────────────────────────────────────────────

  it('returns ALLOW when only matching ALLOW policies exist (no DENY)', () => {
    const policies = [
      buildMatchingPolicy('allow-1', 'ALLOW', 10),
      buildMatchingPolicy('allow-2', 'ALLOW', 5),
    ];

    const result = service.evaluate(policies, EVAL_CTX);

    expect(result.decision).toBe('ALLOW');
  });

  it('returns DENY (implicit) when no policies match', () => {
    const policies = [
      buildNonMatchingPolicy('non-match-allow', 'ALLOW', 10),
      buildNonMatchingPolicy('non-match-deny', 'DENY', 5),
    ];

    const result = service.evaluate(policies, EVAL_CTX);

    expect(result.decision).toBe('DENY');
    // Implicit deny has no matched policy
    expect(result.matchedPolicyId).toBeUndefined();
  });

  it('returns DENY (implicit) for an empty policy set', () => {
    const result = service.evaluate([], EVAL_CTX);

    expect(result.decision).toBe('DENY');
    expect(result.matchedPolicyId).toBeUndefined();
  });

  it('matched policy ID is set to the DENY policy when DENY overrides ALLOW', () => {
    const allowPolicy = buildMatchingPolicy('allow-1', 'ALLOW', 5);
    const denyPolicy = buildMatchingPolicy('deny-1', 'DENY', 1);

    const result = service.evaluate([allowPolicy, denyPolicy], EVAL_CTX);

    expect(result.decision).toBe('DENY');
    expect(result.matchedPolicyId).toBe('deny-1');
  });

  it('non-matching DENY policies do not override matching ALLOW policies', () => {
    const allowPolicy = buildMatchingPolicy('allow-1', 'ALLOW', 5);
    const nonMatchingDeny = buildNonMatchingPolicy('deny-no-match', 'DENY', 100);

    const result = service.evaluate([allowPolicy, nonMatchingDeny], EVAL_CTX);

    expect(result.decision).toBe('ALLOW');
    expect(result.matchedPolicyId).toBe('allow-1');
  });
});

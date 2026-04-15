/**
 * Property-Based Tests for AbacPolicyEngine / AbacJitCompiler
 *
 * Property 20: JIT compiled policy matches DSL interpreter
 *   For all valid DSL conditions and evaluation contexts,
 *   the JIT-compiled function produces the same result as the interpreter.
 *
 * Property 11 (engine-level): ABAC deny-override — full engine integration test
 *   For all policy sets with arbitrary priorities containing at least one matching
 *   DENY policy, AbacPolicyEngine.evaluate() MUST return DENY regardless of
 *   priority ordering, JIT compilation, or caching.
 *
 * Validates: Req 9.1–9.7
 */

import * as fc from 'fast-check';
import { AbacCondition, EvaluationContext } from '../../../domain/value-objects/abac-condition.vo';
import { AbacJitCompiler, AbacPolicyEngine } from './abac-policy-engine';
import { AbacPolicy, AbacEvaluationContext } from '../../../domain/services/abac-policy.domain-service';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { IAbacPolicyRepository } from '../../ports/driven/i-abac-policy.repository';

// ── Arbitraries ───────────────────────────────────────────────────────────────

/** Generate a simple attribute value (string, number, or boolean) */
const primitiveArb = fc.oneof(
  fc.string({ maxLength: 20 }),
  fc.integer({ min: 0, max: 100 }),
  fc.boolean(),
);

/** Generate a flat context record */
const contextRecordArb = fc.dictionary(
  fc.string({ minLength: 1, maxLength: 10 }).filter((s) => /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(s)),
  primitiveArb,
  { minKeys: 0, maxKeys: 5 },
);

/** Generate a full EvaluationContext */
const evalContextArb: fc.Arbitrary<EvaluationContext> = fc.record({
  subject: contextRecordArb,
  resource: contextRecordArb,
  env: contextRecordArb,
});

/**
 * A curated set of valid DSL expressions that cover all operators and logical connectors.
 * We use a fixed set rather than generating arbitrary DSL strings to avoid
 * generating syntactically invalid strings (which would throw on parse, not be a bug).
 */
const validDslExpressions = [
  'subject.role == "admin"',
  'subject.role != "guest"',
  'subject.age >= 18',
  'subject.age <= 65',
  'subject.age > 21',
  'subject.age < 100',
  'subject.role IN ["admin", "editor"]',
  'subject.role NOT IN ["banned", "suspended"]',
  'subject.tags CONTAINS "premium"',
  'subject.role == "admin" AND resource.tenantId == subject.tenantId',
  'subject.role == "admin" OR subject.role == "editor"',
  'NOT (subject.role == "guest")',
  'subject.role IN ["admin", "editor"] AND subject.age >= 18',
  '(subject.role == "admin" OR subject.role == "editor") AND resource.public == false',
  'NOT (resource.classification == "secret" AND subject.clearance < 3)',
  'env.time >= 9 AND env.time <= 17',
  'subject.department == "finance" AND resource.type == "report"',
];

// ── Property 20: JIT Determinism ──────────────────────────────────────────────

describe('AbacJitCompiler — Property 20: JIT compiled result matches interpreter', () => {
  const compiler = new AbacJitCompiler();

  it('compiled function produces same result as interpreter for all contexts', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...validDslExpressions),
        evalContextArb,
        async (dsl, ctx) => {
          const condition = AbacCondition.parse(dsl);

          // Interpreter result
          const interpreted = condition.evaluate(ctx);

          // JIT compiled result
          const compiledFn = compiler.compile(condition);
          const compiled = compiledFn(ctx);

          expect(compiled).toBe(interpreted);
        },
      ),
      { numRuns: 1000 },
    );
  });

  it('getOrCompile returns cached function on second call', () => {
    const dsl = 'subject.role == "admin"';
    const condition = AbacCondition.parse(dsl);

    const fn1 = compiler.getOrCompile('test-policy:1', condition);
    const fn2 = compiler.getOrCompile('test-policy:1', condition);

    // Same reference — returned from cache
    expect(fn1).toBe(fn2);
  });

  it('different cache keys produce independent compiled functions', () => {
    const dsl = 'subject.role == "admin"';
    const condition = AbacCondition.parse(dsl);

    const fn1 = compiler.getOrCompile('policy-a:1', condition);
    const fn2 = compiler.getOrCompile('policy-b:1', condition);

    // Both should produce the same result for the same context
    const ctx: EvaluationContext = { subject: { role: 'admin' }, resource: {}, env: {} };
    expect(fn1(ctx)).toBe(fn2(ctx));
  });
});

// ── Operator coverage ─────────────────────────────────────────────────────────

describe('AbacJitCompiler — operator correctness', () => {
  const compiler = new AbacJitCompiler();

  const cases: Array<{ dsl: string; ctx: EvaluationContext; expected: boolean }> = [
    {
      dsl: 'subject.role == "admin"',
      ctx: { subject: { role: 'admin' }, resource: {}, env: {} },
      expected: true,
    },
    {
      dsl: 'subject.role == "admin"',
      ctx: { subject: { role: 'user' }, resource: {}, env: {} },
      expected: false,
    },
    {
      dsl: 'subject.age >= 18',
      ctx: { subject: { age: 18 }, resource: {}, env: {} },
      expected: true,
    },
    {
      dsl: 'subject.age >= 18',
      ctx: { subject: { age: 17 }, resource: {}, env: {} },
      expected: false,
    },
    {
      dsl: 'subject.role IN ["admin", "editor"]',
      ctx: { subject: { role: 'editor' }, resource: {}, env: {} },
      expected: true,
    },
    {
      dsl: 'subject.role IN ["admin", "editor"]',
      ctx: { subject: { role: 'viewer' }, resource: {}, env: {} },
      expected: false,
    },
    {
      dsl: 'subject.role NOT IN ["banned"]',
      ctx: { subject: { role: 'admin' }, resource: {}, env: {} },
      expected: true,
    },
    {
      dsl: 'subject.tags CONTAINS "premium"',
      ctx: { subject: { tags: ['premium', 'verified'] }, resource: {}, env: {} },
      expected: true,
    },
    {
      dsl: 'NOT (subject.role == "guest")',
      ctx: { subject: { role: 'admin' }, resource: {}, env: {} },
      expected: true,
    },
    {
      dsl: 'subject.role == "admin" AND resource.public == false',
      ctx: { subject: { role: 'admin' }, resource: { public: false }, env: {} },
      expected: true,
    },
    {
      dsl: 'subject.role == "admin" OR subject.role == "editor"',
      ctx: { subject: { role: 'editor' }, resource: {}, env: {} },
      expected: true,
    },
  ];

  for (const { dsl, ctx, expected } of cases) {
    it(`"${dsl}" with given context → ${expected}`, () => {
      const condition = AbacCondition.parse(dsl);
      const fn = compiler.compile(condition);
      expect(fn(ctx)).toBe(expected);
    });
  }
});

// ── Missing attribute handling ────────────────────────────────────────────────

describe('AbacJitCompiler — missing attribute handling', () => {
  const compiler = new AbacJitCompiler();

  it('returns false for == comparison when attribute is missing', () => {
    const condition = AbacCondition.parse('subject.role == "admin"');
    const fn = compiler.compile(condition);
    // subject.role is undefined — should not throw, should return false
    expect(fn({ subject: {}, resource: {}, env: {} })).toBe(false);
  });

  it('returns false for IN comparison when attribute is missing', () => {
    const condition = AbacCondition.parse('subject.role IN ["admin"]');
    const fn = compiler.compile(condition);
    expect(fn({ subject: {}, resource: {}, env: {} })).toBe(false);
  });
});


// ── Property 11 (engine-level): deny-override full integration ────────────────

/**
 * Helpers shared across Property 11 engine tests.
 *
 * We use always-true / always-false DSL strings so that the test controls
 * exactly which policies match, isolating the deny-override logic from
 * condition evaluation correctness (which is covered by Property 20).
 *
 * The engine's toDomainPolicy() calls AbacCondition.parse() on the DSL strings
 * stored in the repository record, so we work with DSL strings throughout.
 */
const ENGINE_TENANT_ID = TenantId.from('b2c3d4e5-f6a7-4890-9bcd-ef0123456789');

const ALWAYS_TRUE_DSL = 'subject.role == "any" OR NOT subject.role == "any"';
const ALWAYS_FALSE_DSL = 'subject.role == "__never_matches__"';

/** Minimal evaluation context — values don't matter for always-true/false conditions. */
const ENGINE_EVAL_CTX: AbacEvaluationContext = {
  subject: { role: 'user', tenantId: ENGINE_TENANT_ID.toString() },
  resource: { type: 'document', id: 'doc-42' },
  action: { name: 'read' },
  env: { time: '14:00' },
};

/** Repository record shape (string DSL conditions) for a policy that always matches. */
function buildMatchingRecord(id: string, effect: 'ALLOW' | 'DENY', priority: number) {
  return {
    id,
    tenantId: ENGINE_TENANT_ID.toString(),
    name: `engine-policy-${id}`,
    effect,
    priority,
    subjectCondition: ALWAYS_TRUE_DSL,
    resourceCondition: ALWAYS_TRUE_DSL,
    actionCondition: ALWAYS_TRUE_DSL,
    createdAt: new Date('2024-01-01T00:00:00Z'),
    updatedAt: new Date('2024-01-01T00:00:00Z'),
  };
}

/** Repository record shape for a policy that never matches (subject is always-false). */
function buildNonMatchingRecord(id: string, effect: 'ALLOW' | 'DENY', priority: number) {
  return {
    id,
    tenantId: ENGINE_TENANT_ID.toString(),
    name: `engine-non-matching-${id}`,
    effect,
    priority,
    subjectCondition: ALWAYS_FALSE_DSL,
    resourceCondition: ALWAYS_TRUE_DSL,
    actionCondition: ALWAYS_TRUE_DSL,
    createdAt: new Date('2024-01-01T00:00:00Z'),
    updatedAt: new Date('2024-01-01T00:00:00Z'),
  };
}

type PolicyRecord = ReturnType<typeof buildMatchingRecord>;

/** Build an AbacPolicyEngine backed by an in-memory mock repository. */
function buildEngineFromRecords(records: PolicyRecord[]): AbacPolicyEngine {
  const mockRepo: IAbacPolicyRepository = {
    findByTenantId: jest.fn().mockResolvedValue(records),
    findById: jest.fn(),
    save: jest.fn(),
    delete: jest.fn(),
  };
  return new AbacPolicyEngine(mockRepo as any, undefined);
}

// ── Arbitraries ───────────────────────────────────────────────────────────────

const enginePriorityArb = fc.integer({ min: -1000, max: 1000 });
const enginePolicyIdArb = fc.uuid();

const engineMatchingAllowArb = fc
  .tuple(enginePolicyIdArb, enginePriorityArb)
  .map(([id, priority]) => buildMatchingRecord(id, 'ALLOW', priority));

const engineMatchingDenyArb = fc
  .tuple(enginePolicyIdArb, enginePriorityArb)
  .map(([id, priority]) => buildMatchingRecord(id, 'DENY', priority));

const engineNonMatchingArb = fc
  .tuple(enginePolicyIdArb, enginePriorityArb, fc.constantFrom<'ALLOW' | 'DENY'>('ALLOW', 'DENY'))
  .map(([id, priority, effect]) => buildNonMatchingRecord(id, effect, priority));

// ── Property 11 (engine-level) ────────────────────────────────────────────────

describe('AbacPolicyEngine — Property 11: deny-override (full engine integration)', () => {
  it(
    'DENY always wins over any number of matching ALLOW policies regardless of priority',
    async () => {
      /**
       * **Property 11: DENY policy overrides ALLOW regardless of priority ordering**
       * **Validates: Req 9.3**
       *
       * For any policy set containing at least one matching DENY policy (with any
       * priority), AbacPolicyEngine.evaluate() MUST return DENY — even when:
       *   - The DENY policy has a lower priority than all ALLOW policies
       *   - Multiple ALLOW policies exist with higher priorities
       *   - Non-matching policies of either effect are present
       *   - The engine uses JIT compilation and LRU caching
       */
      await fc.assert(
        fc.asyncProperty(
          fc.array(engineMatchingAllowArb, { minLength: 0, maxLength: 5 }),
          fc.array(engineMatchingDenyArb, { minLength: 1, maxLength: 3 }),
          fc.array(engineNonMatchingArb, { minLength: 0, maxLength: 3 }),
          async (allowRecords, denyRecords, nonMatchingRecords) => {
            const allRecords = [...allowRecords, ...denyRecords, ...nonMatchingRecords];
            const engine = buildEngineFromRecords(allRecords);

            const result = await engine.evaluate(ENGINE_TENANT_ID, ENGINE_EVAL_CTX);

            expect(result.decision).toBe('DENY');
          },
        ),
        { numRuns: 500 },
      );
    },
    30_000,
  );

  it(
    'DENY wins even when the DENY policy has the lowest possible priority',
    async () => {
      /**
       * **Validates: Req 9.3**
       *
       * Specifically verifies that the engine does not short-circuit on the
       * highest-priority ALLOW and skip lower-priority DENY policies.
       */
      await fc.assert(
        fc.asyncProperty(
          fc.array(fc.integer({ min: 1, max: 1000 }), { minLength: 1, maxLength: 5 }),
          async (allowPriorities) => {
            const allowRecords = allowPriorities.map((p, i) =>
              buildMatchingRecord(`allow-${i}-${p}`, 'ALLOW', p),
            );
            const denyRecord = buildMatchingRecord('deny-lowest', 'DENY', -9999);

            const engine = buildEngineFromRecords([...allowRecords, denyRecord]);
            const result = await engine.evaluate(ENGINE_TENANT_ID, ENGINE_EVAL_CTX);

            expect(result.decision).toBe('DENY');
          },
        ),
        { numRuns: 300 },
      );
    },
    20_000,
  );

  it(
    'DENY wins even when the DENY policy has the highest possible priority',
    async () => {
      /**
       * **Validates: Req 9.3**
       */
      await fc.assert(
        fc.asyncProperty(
          fc.array(fc.integer({ min: -1000, max: 99 }), { minLength: 1, maxLength: 5 }),
          async (allowPriorities) => {
            const allowRecords = allowPriorities.map((p, i) =>
              buildMatchingRecord(`allow-${i}-${p}`, 'ALLOW', p),
            );
            const denyRecord = buildMatchingRecord('deny-highest', 'DENY', 9999);

            const engine = buildEngineFromRecords([...allowRecords, denyRecord]);
            const result = await engine.evaluate(ENGINE_TENANT_ID, ENGINE_EVAL_CTX);

            expect(result.decision).toBe('DENY');
          },
        ),
        { numRuns: 300 },
      );
    },
    20_000,
  );

  it('engine returns ALLOW when only matching ALLOW policies exist (no DENY)', async () => {
    const records = [
      buildMatchingRecord('allow-high', 'ALLOW', 100),
      buildMatchingRecord('allow-low', 'ALLOW', 1),
    ];
    const engine = buildEngineFromRecords(records);

    const result = await engine.evaluate(ENGINE_TENANT_ID, ENGINE_EVAL_CTX);

    expect(result.decision).toBe('ALLOW');
  });

  it('engine returns DENY (implicit) when no policies match', async () => {
    const records = [
      buildNonMatchingRecord('non-match-allow', 'ALLOW', 10),
      buildNonMatchingRecord('non-match-deny', 'DENY', 5),
    ];
    const engine = buildEngineFromRecords(records);

    const result = await engine.evaluate(ENGINE_TENANT_ID, ENGINE_EVAL_CTX);

    expect(result.decision).toBe('DENY');
    expect(result.matchedPolicyId).toBeUndefined();
  });

  it('engine returns DENY (implicit) for an empty policy set', async () => {
    const engine = buildEngineFromRecords([]);

    const result = await engine.evaluate(ENGINE_TENANT_ID, ENGINE_EVAL_CTX);

    expect(result.decision).toBe('DENY');
    expect(result.matchedPolicyId).toBeUndefined();
  });

  it(
    'non-matching DENY policies do not override matching ALLOW policies',
    async () => {
      /**
       * **Validates: Req 9.3 (negative case)**
       *
       * A DENY policy that does NOT match the context must not override a matching ALLOW.
       */
      await fc.assert(
        fc.asyncProperty(
          enginePriorityArb,
          enginePriorityArb,
          async (allowPriority, denyPriority) => {
            const allowRecord = buildMatchingRecord('allow-match', 'ALLOW', allowPriority);
            const nonMatchingDeny = buildNonMatchingRecord('deny-no-match', 'DENY', denyPriority);

            const engine = buildEngineFromRecords([allowRecord, nonMatchingDeny]);
            const result = await engine.evaluate(ENGINE_TENANT_ID, ENGINE_EVAL_CTX);

            expect(result.decision).toBe('ALLOW');
          },
        ),
        { numRuns: 200 },
      );
    },
    15_000,
  );

  it(
    'deny-override holds after cache is populated (second evaluate call uses cached policies)',
    async () => {
      /**
       * **Validates: Req 9.3, Req 9.8**
       *
       * Verifies that the LRU policy cache does not corrupt the deny-override
       * guarantee — the second call (cache hit) must produce the same DENY result.
       */
      await fc.assert(
        fc.asyncProperty(
          fc.array(engineMatchingAllowArb, { minLength: 1, maxLength: 4 }),
          engineMatchingDenyArb,
          async (allowRecords, denyRecord) => {
            const engine = buildEngineFromRecords([...allowRecords, denyRecord]);

            // First call — populates cache
            const first = await engine.evaluate(ENGINE_TENANT_ID, ENGINE_EVAL_CTX);
            // Second call — cache hit
            const second = await engine.evaluate(ENGINE_TENANT_ID, ENGINE_EVAL_CTX);

            expect(first.decision).toBe('DENY');
            expect(second.decision).toBe('DENY');
          },
        ),
        { numRuns: 200 },
      );
    },
    15_000,
  );
});

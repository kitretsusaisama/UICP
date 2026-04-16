import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { AbacCondition, EvaluationContext } from '../../../domain/value-objects/abac-condition.vo';
import { AbacPolicyDomainService, AbacEvaluationContext, AbacEvaluationResult } from '../../../domain/services/abac-policy.domain-service';
import { IAbacPolicyRepository, AbacPolicy as AbacPolicyRecord } from '../../ports/driven/i-abac-policy.repository';
import { IMetricsPort } from '../../ports/driven/i-metrics.port';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { AbacPolicy } from '../../../domain/services/abac-policy.domain-service';

// ── LRU Cache ─────────────────────────────────────────────────────────────────

/**
 * Minimal LRU cache implementation — avoids external dependency.
 * Evicts least-recently-used entry when capacity is exceeded.
 */
class LruCache<K, V> {
  private readonly map = new Map<K, { value: V; expiresAt: number }>();

  constructor(
    private readonly capacity: number,
    private readonly ttlMs: number,
  ) {}

  get(key: K): V | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return undefined;
    }
    // Refresh position (LRU: delete + re-insert)
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.value;
  }

  set(key: K, value: V): void {
    if (this.map.has(key)) this.map.delete(key);
    else if (this.map.size >= this.capacity) {
      // Evict oldest (first) entry
      const firstKey = this.map.keys().next().value;
      if (firstKey !== undefined) this.map.delete(firstKey);
    }
    this.map.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }

  delete(key: K): void {
    this.map.delete(key);
  }

  size(): number {
    return this.map.size;
  }
}

// ── JIT Compiler ──────────────────────────────────────────────────────────────

/**
 * Compiled policy function signature.
 * Receives the evaluation context and returns a boolean.
 */
type CompiledConditionFn = (ctx: EvaluationContext) => boolean;

/**
 * Compiles an AbacCondition AST to a native JavaScript function via `new Function(...)`.
 * The compiled function is semantically equivalent to `condition.evaluate(ctx)` but
 * avoids the interpreter overhead on hot paths.
 *
 * Caches compiled functions in LRU(500) keyed by `policyId:version`.
 */
export class AbacJitCompiler {
  private readonly cache = new LruCache<string, CompiledConditionFn>(500, Infinity);

  /**
   * Get or compile a condition function for the given policy.
   * @param cacheKey  Unique key — typically `${policyId}:${version}` or a DSL hash.
   * @param condition The AbacCondition value object to compile.
   */
  getOrCompile(cacheKey: string, condition: AbacCondition): CompiledConditionFn {
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    const fn = this.compile(condition);
    this.cache.set(cacheKey, fn);
    return fn;
  }

  /**
   * Wraps the `AbacCondition` `evaluate()` interpreter method.
   * Completely removes `new Function` Remote Code Execution vectors.
   */
  compile(condition: AbacCondition): CompiledConditionFn {
    return (ctx: EvaluationContext) => condition.evaluate(ctx);
  }
}

// ── Policy Engine ─────────────────────────────────────────────────────────────

/**
 * AbacPolicyEngine — application service that orchestrates policy loading,
 * JIT compilation, caching, and evaluation.
 *
 * - Tenant policy cache: LRU(100 tenants) with 60s TTL
 * - Compiled function cache: LRU(500) keyed by `policyId:version`
 * - Deny-override algorithm via AbacPolicyDomainService
 *
 * Implements: Req 9.1–9.11
 */
@Injectable()
export class AbacPolicyEngine {
  private readonly logger = new Logger(AbacPolicyEngine.name);

  /** LRU(100 tenants) with 60s TTL — stores parsed + compiled policies */
  private readonly tenantCache = new LruCache<string, AbacPolicy[]>(100, 60_000);

  private readonly jitCompiler = new AbacJitCompiler();
  private readonly domainService = new AbacPolicyDomainService();

  constructor(
    @Inject(INJECTION_TOKENS.ABAC_POLICY_REPOSITORY)
    private readonly policyRepository: IAbacPolicyRepository,

    @Optional()
    @Inject(INJECTION_TOKENS.METRICS_PORT)
    private readonly metrics: IMetricsPort | undefined,
  ) {}

  /**
   * Evaluate all tenant policies against the given context.
   * Uses deny-override algorithm: any matching DENY wins over all ALLOWs.
   * Implicit deny when no policy matches.
   */
  async evaluate(tenantId: TenantId, context: AbacEvaluationContext): Promise<AbacEvaluationResult> {
    const start = Date.now();
    const policies = await this.loadPolicies(tenantId);

    const result = this.domainService.evaluate(policies, context);

    const elapsed = Date.now() - start;
    this.metrics?.histogram('uicp_abac_evaluation_duration_ms', elapsed, {
      tenant_id: tenantId.toString(),
      decision: result.decision,
    });

    return result;
  }

  /**
   * Evaluate a single DSL condition string against a context (dry-run).
   * Does NOT load tenant policies — evaluates the provided condition directly.
   */
  evaluateCondition(dsl: string, context: EvaluationContext): { result: boolean; executionTimeMs: number; warnings: string[] } {
    const warnings: string[] = [];
    const start = Date.now();

    const condition = AbacCondition.parse(dsl);

    // Check for missing attributes and emit warnings
    const ast = condition.toJSON() as Record<string, unknown>;
    this.collectMissingAttributeWarnings(ast, context, warnings);

    const compiledFn = this.jitCompiler.compile(condition);
    const result = compiledFn(context);

    return { result, executionTimeMs: Date.now() - start, warnings };
  }

  /**
   * Simulate all tenant policies against a context and return which ones matched.
   */
  async simulate(tenantId: TenantId, context: AbacEvaluationContext): Promise<{
    decision: 'ALLOW' | 'DENY' | 'NO_MATCH';
    matchedPolicies: Array<{ policyId: string; name: string; effect: 'ALLOW' | 'DENY'; priority: number; matched: boolean }>;
    effectivePolicies: number;
    evaluationTimeMs: number;
  }> {
    const start = Date.now();
    const policies = await this.loadPolicies(tenantId);

    const evalCtx: EvaluationContext = {
      subject: context.subject,
      resource: context.resource,
      env: { ...context.env, action: context.action },
    };

    const matchedPolicies = policies.map((policy) => {
      const subjectMatch = policy.subjectCondition.evaluate(evalCtx);
      const resourceMatch = policy.resourceCondition.evaluate(evalCtx);
      const actionCtx: EvaluationContext = { subject: context.subject, resource: context.action, env: evalCtx.env };
      const actionMatch = policy.actionCondition.evaluate(actionCtx);
      const matched = subjectMatch && resourceMatch && actionMatch;
      return {
        policyId: policy.id,
        name: policy.name,
        effect: policy.effect,
        priority: policy.priority,
        matched,
      };
    });

    const result = this.domainService.evaluate(policies, context);
    const anyMatched = matchedPolicies.some((p) => p.matched);
    const decision = anyMatched ? result.decision : 'NO_MATCH';

    return {
      decision,
      matchedPolicies,
      effectivePolicies: policies.length,
      evaluationTimeMs: Date.now() - start,
    };
  }

  /**
   * Invalidate the tenant's policy cache immediately.
   * Called on policy create/update/delete.
   */
  invalidateTenantCache(tenantId: TenantId): void {
    this.tenantCache.delete(tenantId.toString());
    this.logger.debug({ tenantId: tenantId.toString() }, 'ABAC policy cache invalidated');
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async loadPolicies(tenantId: TenantId): Promise<AbacPolicy[]> {
    const cacheKey = tenantId.toString();
    const cached = this.tenantCache.get(cacheKey);
    if (cached) return cached;

    const records = await this.policyRepository.findByTenantId(tenantId);
    const policies = records.map((r) => this.toDomainPolicy(r));

    this.tenantCache.set(cacheKey, policies);
    return policies;
  }

  private toDomainPolicy(record: AbacPolicyRecord): AbacPolicy {
    const cacheKey = `${record.id}:${record.updatedAt.getTime()}`;

    const subjectCondition = AbacCondition.parse(record.subjectCondition);
    const resourceCondition = AbacCondition.parse(record.resourceCondition);
    const actionCondition = AbacCondition.parse(record.actionCondition);

    // Pre-compile all three conditions and cache them
    this.jitCompiler.getOrCompile(`${cacheKey}:subject`, subjectCondition);
    this.jitCompiler.getOrCompile(`${cacheKey}:resource`, resourceCondition);
    this.jitCompiler.getOrCompile(`${cacheKey}:action`, actionCondition);

    return {
      id: record.id,
      tenantId: TenantId.from(record.tenantId),
      name: record.name,
      effect: record.effect,
      priority: record.priority,
      subjectCondition,
      resourceCondition,
      actionCondition,
    };
  }

  private collectMissingAttributeWarnings(
    node: Record<string, unknown>,
    context: EvaluationContext,
    warnings: string[],
  ): void {
    if (node['kind'] === 'comparison') {
      const left = node['left'] as Record<string, unknown>;
      if (left['kind'] === 'attribute') {
        const prefix = left['prefix'] as string;
        const path = left['path'] as string;
        const parts = path.split('.');
        let current: unknown = context[prefix as keyof EvaluationContext];
        for (const part of parts) {
          if (current === null || current === undefined || typeof current !== 'object') {
            warnings.push(`attribute '${prefix}.${path}' not found in context`);
            break;
          }
          current = (current as Record<string, unknown>)[part];
        }
      }
    } else if (node['kind'] === 'logical') {
      this.collectMissingAttributeWarnings(node['left'] as Record<string, unknown>, context, warnings);
      this.collectMissingAttributeWarnings(node['right'] as Record<string, unknown>, context, warnings);
    } else if (node['kind'] === 'not') {
      this.collectMissingAttributeWarnings(node['operand'] as Record<string, unknown>, context, warnings);
    }
  }
}

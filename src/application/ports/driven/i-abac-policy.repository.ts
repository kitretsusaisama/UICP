import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

/** Effect of an ABAC policy evaluation. */
export type PolicyEffect = 'ALLOW' | 'DENY';

/** Compiled ABAC policy record. */
export interface AbacPolicy {
  id: string;
  tenantId: string;
  name: string;
  effect: PolicyEffect;
  /** Higher priority policies are evaluated first. */
  priority: number;
  subjectCondition: string;
  resourceCondition: string;
  actionCondition: string;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Driven port — ABAC policy persistence (Section 4.3).
 *
 * Contract:
 * - `findByTenantId` returns policies sorted by `priority DESC`.
 * - Results are cached in LRU(100 tenants) with 60s TTL.
 * - Cache is invalidated on `save()` or `delete()`.
 * - Tenant isolation: `findByTenantId` MUST NOT return policies from other tenants.
 */
export interface IAbacPolicyRepository {
  /**
   * Load all active policies for a tenant.
   * Cached in LRU(100) with 60s TTL; sorted by priority DESC.
   */
  findByTenantId(tenantId: TenantId): Promise<AbacPolicy[]>;

  /**
   * Find a single policy by ID within a tenant.
   */
  findById(policyId: string, tenantId: TenantId): Promise<AbacPolicy | null>;

  /**
   * Persist a new or updated policy.
   * Invalidates the tenant's policy cache.
   */
  save(policy: AbacPolicy): Promise<void>;

  /**
   * Soft-delete a policy.
   * Invalidates the tenant's policy cache.
   */
  delete(policyId: string, tenantId: TenantId): Promise<void>;
}

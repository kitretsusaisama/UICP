import { Inject, Injectable } from '@nestjs/common';
import {
  IAbacPolicyRepository,
  AbacPolicy,
  PolicyEffect,
} from '../../../application/ports/driven/i-abac-policy.repository';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { MYSQL_POOL, DbPool } from './mysql.module';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';

function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface AbacPolicyRow {
  id: Buffer;
  tenant_id: Buffer;
  name: string;
  effect: string;
  priority: number;
  subject_condition: string;
  resource_condition: string;
  action_condition: string;
  enabled: number;
  version: number;
  created_at: Date;
  updated_at: Date;
}

function rowToPolicy(row: AbacPolicyRow): AbacPolicy {
  return {
    id: bufferToUuid(row.id),
    tenantId: bufferToUuid(row.tenant_id),
    name: row.name,
    effect: row.effect.toUpperCase() as PolicyEffect,
    priority: row.priority,
    subjectCondition: row.subject_condition,
    resourceCondition: row.resource_condition,
    actionCondition: row.action_condition,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** Cache TTL for tenant policy lists — 60 seconds (Req 9.8). */
const POLICY_CACHE_TTL_S = 60;

function policyCacheKey(tenantId: string): string {
  return `abac:policies:${tenantId}`;
}

/**
 * MySQL implementation of IAbacPolicyRepository.
 *
 * - findByTenantId() returns policies sorted by priority DESC.
 * - Results are cached in Redis with a 60-second TTL (Req 9.8).
 * - Cache is invalidated on save() and delete() (Req 9.9).
 * - Tenant isolation: all queries include WHERE tenant_id = ?.
 */
@Injectable()
export class MysqlAbacPolicyRepository implements IAbacPolicyRepository {
  constructor(
    @Inject(MYSQL_POOL) private readonly pool: DbPool,
    @Inject(INJECTION_TOKENS.CACHE_PORT) private readonly cache: ICachePort,
  ) {}

  async findByTenantId(tenantId: TenantId): Promise<AbacPolicy[]> {
    const cacheKey = policyCacheKey(tenantId.toString());
    const cached = await this.cache.get(cacheKey);
    if (cached) {
      return JSON.parse(cached) as AbacPolicy[];
    }

    const [rows] = await this.pool.execute<AbacPolicyRow[]>(
      `SELECT id, tenant_id, name, effect, priority,
              subject_condition, resource_condition, action_condition,
              enabled, version, created_at, updated_at
         FROM abac_policies
        WHERE tenant_id = ?
          AND enabled   = 1
        ORDER BY priority DESC`,
      [uuidToBuffer(tenantId.toString())],
    );

    const policies = (rows as AbacPolicyRow[]).map(rowToPolicy);
    await this.cache.set(cacheKey, JSON.stringify(policies), POLICY_CACHE_TTL_S);
    return policies;
  }

  async findById(policyId: string, tenantId: TenantId): Promise<AbacPolicy | null> {
    const [rows] = await this.pool.execute<AbacPolicyRow[]>(
      `SELECT id, tenant_id, name, effect, priority,
              subject_condition, resource_condition, action_condition,
              enabled, version, created_at, updated_at
         FROM abac_policies
        WHERE id        = ?
          AND tenant_id = ?
        LIMIT 1`,
      [uuidToBuffer(policyId), uuidToBuffer(tenantId.toString())],
    );

    const row = (rows as AbacPolicyRow[])[0];
    return row ? rowToPolicy(row) : null;
  }

  async save(policy: AbacPolicy): Promise<void> {
    await this.pool.execute(
      `INSERT INTO abac_policies
         (id, tenant_id, name, effect, priority,
          subject_condition, resource_condition, action_condition,
          enabled, version, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
       ON DUPLICATE KEY UPDATE
         name               = VALUES(name),
         effect             = VALUES(effect),
         priority           = VALUES(priority),
         subject_condition  = VALUES(subject_condition),
         resource_condition = VALUES(resource_condition),
         action_condition   = VALUES(action_condition),
         version            = version + 1,
         updated_at         = VALUES(updated_at)`,
      [
        uuidToBuffer(policy.id),
        uuidToBuffer(policy.tenantId),
        policy.name,
        policy.effect.toLowerCase(),
        policy.priority,
        policy.subjectCondition,
        policy.resourceCondition,
        policy.actionCondition,
        policy.createdAt,
        policy.updatedAt,
      ],
    );

    await this._invalidateCache(policy.tenantId);
  }

  async delete(policyId: string, tenantId: TenantId): Promise<void> {
    await this.pool.execute(
      `UPDATE abac_policies
          SET enabled    = 0,
              updated_at = NOW()
        WHERE id        = ?
          AND tenant_id = ?`,
      [uuidToBuffer(policyId), uuidToBuffer(tenantId.toString())],
    );

    await this._invalidateCache(tenantId.toString());
  }

  private async _invalidateCache(tenantId: string): Promise<void> {
    await this.cache.del(policyCacheKey(tenantId));
  }
}

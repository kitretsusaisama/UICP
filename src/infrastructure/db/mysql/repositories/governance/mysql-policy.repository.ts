import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { IPolicyRepository } from '../../../../../domain/repositories/governance/policy.repository.interface';
import { Policy } from '../../../../../domain/entities/governance/policy.entity';

@Injectable()
export class MysqlPolicyRepository implements IPolicyRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async save(policy: Policy): Promise<void> {
    const query = `
      INSERT INTO abac_policies (id, tenant_id, name, description, effect, conditions, status, version, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        description = VALUES(description),
        effect = VALUES(effect),
        conditions = VALUES(conditions),
        status = VALUES(status),
        version = VALUES(version),
        updated_at = VALUES(updated_at)
    `;
    await this.pool.execute(query, [
      policy.id,
      policy.tenantId,
      policy.name,
      policy.description,
      policy.rules.effect,
      JSON.stringify(policy.rules.conditions),
      policy.status,
      policy.version,
      policy.createdAt,
      policy.updatedAt,
    ]);
  }

  async findByIdAndTenant(id: string, tenantId: string): Promise<Policy | null> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM abac_policies WHERE id = ? AND tenant_id = ?',
      [id, tenantId]
    );

    if (rows.length === 0) return null;
    const row = rows[0];

    return new Policy({
      id: row.id,
      tenantId: row.tenant_id,
      name: row.name,
      description: row.description,
      rules: {
        effect: row.effect,
        conditions: typeof row.conditions === 'string' ? JSON.parse(row.conditions) : row.conditions,
      },
      status: row.status,
      version: row.version,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    });
  }

  async findByTenant(tenantId: string): Promise<Policy[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM abac_policies WHERE tenant_id = ? ORDER BY created_at DESC',
      [tenantId]
    );

    return rows.map((row: any) => new Policy({
      id: row.id,
      tenantId: row.tenant_id,
      name: row.name,
      description: row.description,
      rules: {
        effect: row.effect,
        conditions: typeof row.conditions === 'string' ? JSON.parse(row.conditions) : row.conditions,
      },
      status: row.status,
      version: row.version,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    }));
  }
}

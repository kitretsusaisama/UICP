import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { IRoleRepository } from '../../../../../domain/repositories/governance/role.repository.interface';
import { Role } from '../../../../../domain/entities/governance/role.entity';

@Injectable()
export class MysqlRoleRepository implements IRoleRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async save(role: Role): Promise<void> {
    const query = `
      INSERT INTO roles (id, tenant_id, name, description, version, permissions, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        description = VALUES(description),
        version = VALUES(version),
        permissions = VALUES(permissions),
        updated_at = VALUES(updated_at)
    `;
    await this.pool.execute(query, [
      role.id,
      role.tenantId,
      role.name,
      role.description,
      role.version,
      JSON.stringify(role.permissions),
      role.createdAt,
      role.updatedAt,
    ]);
  }

  async findByIdAndTenant(id: string, tenantId: string): Promise<Role | null> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM roles WHERE id = ? AND tenant_id = ?',
      [id, tenantId]
    );

    if (rows.length === 0) return null;
    const row = rows[0];

    return new Role({
      id: row.id,
      tenantId: row.tenant_id,
      name: row.name,
      description: row.description,
      version: row.version,
      permissions: typeof row.permissions === 'string' ? JSON.parse(row.permissions) : row.permissions,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    });
  }

  async findByTenant(tenantId: string): Promise<Role[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM roles WHERE tenant_id = ? ORDER BY name ASC',
      [tenantId]
    );

    return rows.map((row: any) => new Role({
      id: row.id,
      tenantId: row.tenant_id,
      name: row.name,
      description: row.description,
      version: row.version,
      permissions: typeof row.permissions === 'string' ? JSON.parse(row.permissions) : row.permissions,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    }));
  }

  async delete(id: string, tenantId: string): Promise<void> {
    await this.pool.execute('DELETE FROM roles WHERE id = ? AND tenant_id = ?', [id, tenantId]);
  }
}

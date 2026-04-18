import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { IRoleAssignmentRepository } from '../../../../../domain/repositories/governance/role-assignment.repository.interface';
import { RoleAssignment } from '../../../../../domain/entities/governance/role-assignment.entity';

@Injectable()
export class MysqlRoleAssignmentRepository implements IRoleAssignmentRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async save(assignment: RoleAssignment): Promise<void> {
    const query = `
      INSERT INTO role_assignments (id, tenant_id, user_id, role_id, assigned_by, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        expires_at = VALUES(expires_at)
    `;
    await this.pool.execute(query, [
      assignment.id,
      assignment.tenantId,
      assignment.userId,
      assignment.roleId,
      assignment.assignedBy,
      assignment.createdAt,
      assignment.expiresAt,
    ]);
  }

  async findByUserAndTenant(userId: string, tenantId: string): Promise<RoleAssignment[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM role_assignments WHERE user_id = ? AND tenant_id = ?',
      [userId, tenantId]
    );

    return rows.map((row: any) => new RoleAssignment({
      id: row.id,
      tenantId: row.tenant_id,
      userId: row.user_id,
      roleId: row.role_id,
      assignedBy: row.assigned_by,
      createdAt: new Date(row.created_at),
      expiresAt: row.expires_at ? new Date(row.expires_at) : null,
    }));
  }

  async findByRoleAndTenant(roleId: string, tenantId: string): Promise<RoleAssignment[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM role_assignments WHERE role_id = ? AND tenant_id = ?',
      [roleId, tenantId]
    );

    return rows.map((row: any) => new RoleAssignment({
      id: row.id,
      tenantId: row.tenant_id,
      userId: row.user_id,
      roleId: row.role_id,
      assignedBy: row.assigned_by,
      createdAt: new Date(row.created_at),
      expiresAt: row.expires_at ? new Date(row.expires_at) : null,
    }));
  }

  async revoke(userId: string, roleId: string, tenantId: string): Promise<void> {
    await this.pool.execute(
      'DELETE FROM role_assignments WHERE user_id = ? AND role_id = ? AND tenant_id = ?',
      [userId, roleId, tenantId]
    );
  }

  async countByUserAndTenant(userId: string, tenantId: string): Promise<number> {
    const [rows]: any = await this.pool.execute(
      'SELECT COUNT(*) as count FROM role_assignments WHERE user_id = ? AND tenant_id = ? AND (expires_at IS NULL OR expires_at > NOW())',
      [userId, tenantId]
    );
    return parseInt(rows[0].count, 10);
  }
}

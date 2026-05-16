import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { IPlatformRoleAssignmentRepository } from '../../../../../domain/repositories/platform/platform-role.repository.interface';
import { PlatformIdentityRoleAssignment, PlatformIdentityRoleAssignmentProps } from '../../../../../domain/entities/platform/platform-identity-role-assignment.entity';
import { PlatformRoleType, PlatformRoleAssignmentType } from '../../../../../domain/entities/platform/platform-role.entity';

interface Row {
  id: string; platform_identity_id: string; role_id: string; role_type: string;
  assignment_type: string; assigned_by: string; assigned_at: Date;
  activated_at: Date | null; expires_at: Date | null; justification: string | null;
  deactivated_at: Date | null; deactivation_reason: string | null;
}

@Injectable()
export class MysqlPlatformRoleAssignmentRepository implements IPlatformRoleAssignmentRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async findById(id: string): Promise<PlatformIdentityRoleAssignment | null> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_identity_role_assignments WHERE id = ?', [id]);
    if (rows.length === 0) return null;
    return this.rowToEntity(rows[0]);
  }

  async findByIdentityId(identityId: string): Promise<PlatformIdentityRoleAssignment[]> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_identity_role_assignments WHERE platform_identity_id = ? ORDER BY assigned_at DESC', [identityId]);
    return rows.map((row: any) => this.rowToEntity(row));
  }

  async findActiveByIdentityId(identityId: string): Promise<PlatformIdentityRoleAssignment[]> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_identity_role_assignments WHERE platform_identity_id = ? AND deactivated_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY assigned_at DESC', [identityId]);
    return rows.map((row: any) => this.rowToEntity(row));
  }

  async findByRoleId(roleId: string): Promise<PlatformIdentityRoleAssignment[]> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_identity_role_assignments WHERE role_id = ? ORDER BY assigned_at DESC', [roleId]);
    return rows.map((row: any) => this.rowToEntity(row));
  }

  async findEligibleByIdentityId(identityId: string): Promise<PlatformIdentityRoleAssignment[]> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_identity_role_assignments WHERE platform_identity_id = ? AND assignment_type = ? AND deactivated_at IS NULL', [identityId, PlatformRoleAssignmentType.ELIGIBLE]);
    return rows.map((row: any) => this.rowToEntity(row));
  }

  async save(entity: PlatformIdentityRoleAssignment): Promise<PlatformIdentityRoleAssignment> {
    const query = `INSERT INTO platform_identity_role_assignments (id, platform_identity_id, role_id, role_type, assignment_type, assigned_by, assigned_at, activated_at, expires_at, justification, deactivated_at, deactivation_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE activated_at = VALUES(activated_at), expires_at = VALUES(expires_at), deactivated_at = VALUES(deactivated_at), deactivation_reason = VALUES(deactivation_reason)`;
    await this.pool.execute(query, [entity.id, entity.platformIdentityId, entity.roleId, entity.roleType, entity.assignmentType, entity.assignedBy, entity.assignedAt, entity.activatedAt, entity.expiresAt, entity.justification, entity.deactivatedAt, entity.deactivationReason]);
    return entity;
  }

  async delete(id: string): Promise<void> { await this.pool.execute('DELETE FROM platform_identity_role_assignments WHERE id = ?', [id]); }

  private rowToEntity(row: Row): PlatformIdentityRoleAssignment {
    return new PlatformIdentityRoleAssignment({ id: row.id, platformIdentityId: row.platform_identity_id, roleId: row.role_id, roleType: row.role_type as PlatformRoleType, assignmentType: row.assignment_type as PlatformRoleAssignmentType, assignedBy: row.assigned_by, assignedAt: new Date(row.assigned_at), activatedAt: row.activated_at ? new Date(row.activated_at) : undefined, expiresAt: row.expires_at ? new Date(row.expires_at) : undefined, justification: row.justification ?? undefined, deactivatedAt: row.deactivated_at ? new Date(row.deactivated_at) : undefined, deactivationReason: row.deactivation_reason ?? undefined });
  }
}
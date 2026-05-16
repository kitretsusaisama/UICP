import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { IPlatformRoleRepository } from '../../../../../domain/repositories/platform/platform-role.repository.interface';
import { PlatformRole, PlatformRoleType, PlatformRoleAssignmentType } from '../../../../../domain/entities/platform/platform-role.entity';

interface PlatformRoleRow {
  id: string; type: string; name: string; description: string;
  assignment_type: string; is_system: boolean; can_assign: boolean;
  can_delegate: boolean; inheritance_level: number;
  parent_role_id: string | null; permissions: string;
  created_at: Date; updated_at: Date;
}

@Injectable()
export class MysqlPlatformRoleRepository implements IPlatformRoleRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async findById(id: string): Promise<PlatformRole | null> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_roles WHERE id = ?', [id]);
    if (rows.length === 0) return null;
    return this.rowToEntity(rows[0]);
  }

  async findByType(type: string): Promise<PlatformRole | null> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_roles WHERE type = ?', [type]);
    if (rows.length === 0) return null;
    return this.rowToEntity(rows[0]);
  }

  async findAll(): Promise<PlatformRole[]> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_roles ORDER BY inheritance_level ASC');
    return rows.map((row: any) => this.rowToEntity(row));
  }

  async findSystemRoles(): Promise<PlatformRole[]> {
    const [rows]: any = await this.pool.execute('SELECT * FROM platform_roles WHERE is_system = true ORDER BY inheritance_level ASC');
    return rows.map((row: any) => this.rowToEntity(row));
  }

  async save(entity: PlatformRole): Promise<PlatformRole> {
    const query = `INSERT INTO platform_roles (id, type, name, description, assignment_type, is_system, can_assign, can_delegate, inheritance_level, parent_role_id, permissions, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), assignment_type = VALUES(assignment_type), can_assign = VALUES(can_assign), can_delegate = VALUES(can_delegate), parent_role_id = VALUES(parent_role_id), permissions = VALUES(permissions), updated_at = VALUES(updated_at)`;
    await this.pool.execute(query, [entity.id, entity.type, entity.name, entity.description, entity.assignmentType, entity.isSystem, entity.canAssign, entity.canDelegate, entity.inheritanceLevel, entity.parentRoleId, JSON.stringify(entity.permissions), entity.createdAt, entity.updatedAt]);
    return entity;
  }

  private rowToEntity(row: PlatformRoleRow): PlatformRole {
    return new PlatformRole({ id: row.id, type: row.type as PlatformRoleType, name: row.name, description: row.description, assignmentType: row.assignment_type as PlatformRoleAssignmentType, isSystem: row.is_system, canAssign: row.can_assign, canDelegate: row.can_delegate, inheritanceLevel: row.inheritance_level, parentRoleId: row.parent_role_id ?? undefined, permissions: JSON.parse(row.permissions), createdAt: new Date(row.created_at), updatedAt: new Date(row.updated_at) });
  }
}
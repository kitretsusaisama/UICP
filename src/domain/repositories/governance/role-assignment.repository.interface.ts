import { RoleAssignment } from '../../entities/governance/role-assignment.entity';

export const ROLE_ASSIGNMENT_REPOSITORY = 'ROLE_ASSIGNMENT_REPOSITORY';

export interface IRoleAssignmentRepository {
  save(assignment: RoleAssignment): Promise<void>;
  findByUserAndTenant(userId: string, tenantId: string): Promise<RoleAssignment[]>;
  findByRoleAndTenant(roleId: string, tenantId: string): Promise<RoleAssignment[]>;
  revoke(userId: string, roleId: string, tenantId: string): Promise<void>;
  countByUserAndTenant(userId: string, tenantId: string): Promise<number>;
}

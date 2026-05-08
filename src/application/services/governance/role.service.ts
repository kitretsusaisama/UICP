import { Injectable, Inject, NotFoundException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { IRoleRepository, ROLE_REPOSITORY } from '../../../domain/repositories/governance/role.repository.interface';
import { IRoleAssignmentRepository, ROLE_ASSIGNMENT_REPOSITORY } from '../../../domain/repositories/governance/role-assignment.repository.interface';
import { Role } from '../../../domain/entities/governance/role.entity';
import { RoleAssignment } from '../../../domain/entities/governance/role-assignment.entity';

@Injectable()
export class RoleService {
  constructor(
    @Inject(ROLE_REPOSITORY) private readonly roleRepository: IRoleRepository,
    @Inject(ROLE_ASSIGNMENT_REPOSITORY) private readonly assignmentRepository: IRoleAssignmentRepository,
  ) {}

  async createRole(tenantId: string, name: string, permissions: string[], description?: string): Promise<Role> {
    const role = new Role({
      id: uuidv4(),
      tenantId,
      name,
      description,
      permissions,
      version: 1,
    });

    await this.roleRepository.save(role);
    return role;
  }

  async listRoles(tenantId: string): Promise<Role[]> {
    return this.roleRepository.findByTenant(tenantId);
  }

  async assignRole(
    tenantId: string,
    assignedBy: string,
    userId: string,
    roleId: string,
    expiresAt?: string,
  ): Promise<RoleAssignment> {

    // 1. Verify Role exists in Tenant
    const role = await this.roleRepository.findByIdAndTenant(roleId, tenantId);
    if (!role) {
      throw new NotFoundException('Role not found or does not belong to your tenant');
    }

    // 2. Exploding user roles guard: Limit max roles per user (10)
    const currentAssignmentsCount = await this.assignmentRepository.countByUserAndTenant(userId, tenantId);
    if (currentAssignmentsCount >= 10) {
      throw new ForbiddenException('User has reached the maximum number of assigned roles (10)');
    }

    const assignment = new RoleAssignment({
      id: uuidv4(),
      tenantId,
      userId,
      roleId,
      assignedBy,
      expiresAt: expiresAt ? new Date(expiresAt) : null,
    });

    await this.assignmentRepository.save(assignment);
    return assignment;
  }
}

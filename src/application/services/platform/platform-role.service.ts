import { Injectable, NotFoundException } from '@nestjs/common';
import { IPlatformRoleRepository, IPlatformRoleAssignmentRepository } from '../../../domain/repositories/platform/platform-role.repository.interface';
import { PlatformRole, PlatformRoleType, PlatformRoleAssignmentType } from '../../../domain/entities/platform/platform-role.entity';
import { PlatformIdentityRoleAssignment } from '../../../domain/entities/platform/platform-identity-role-assignment.entity';

export interface AssignRoleInput {
  platformIdentityId: string;
  roleId: string;
  roleType: PlatformRoleType;
  assignmentType: PlatformRoleAssignmentType;
  assignedBy: string;
  justification?: string;
  expiresAt?: Date;
}

export interface ActivateRoleInput {
  identityId: string;
  assignmentId: string;
  until?: Date;
}

@Injectable()
export class PlatformRoleService {
  constructor(
    private readonly platformRoleRepository: IPlatformRoleRepository,
    private readonly platformRoleAssignmentRepository: IPlatformRoleAssignmentRepository,
  ) {}

  async bootstrapSystemRoles(): Promise<PlatformRole[]> {
    const savedRoles: PlatformRole[] = [];

    for (const roleProps of PlatformRole.SYSTEM_ROLES) {
      const existing = await this.platformRoleRepository.findById(roleProps.id);
      if (!existing) {
        const role = new PlatformRole(roleProps);
        const saved = await this.platformRoleRepository.save(role);
        savedRoles.push(saved);
      }
    }

    return savedRoles;
  }

  async getRoleById(id: string): Promise<PlatformRole> {
    const role = await this.platformRoleRepository.findById(id);
    if (!role) {
      throw new NotFoundException('Platform role not found');
    }
    return role;
  }

  async getRoleByType(type: PlatformRoleType): Promise<PlatformRole> {
    const role = await this.platformRoleRepository.findByType(type);
    if (!role) {
      throw new NotFoundException(`Platform role type ${type} not found`);
    }
    return role;
  }

  async listAllRoles(): Promise<PlatformRole[]> {
    return this.platformRoleRepository.findAll();
  }

  async listSystemRoles(): Promise<PlatformRole[]> {
    return this.platformRoleRepository.findSystemRoles();
  }

  async assignRole(input: AssignRoleInput): Promise<PlatformIdentityRoleAssignment> {
    const role = await this.getRoleById(input.roleId);
    const assignmentType = input.assignmentType === PlatformRoleAssignmentType.ELIGIBLE && !role.requiresJit
      ? PlatformRoleAssignmentType.PERMANENT
      : input.assignmentType;

    const assignment = PlatformIdentityRoleAssignment.create({
      platformIdentityId: input.platformIdentityId,
      roleId: input.roleId,
      roleType: input.roleType,
      assignmentType,
      assignedBy: input.assignedBy,
      justification: input.justification,
      expiresAt: input.expiresAt,
    });

    if (assignment.assignmentType === PlatformRoleAssignmentType.PERMANENT) {
      assignment.activate();
    }

    return this.platformRoleAssignmentRepository.save(assignment);
  }

  async getAssignmentsByIdentity(identityId: string): Promise<PlatformIdentityRoleAssignment[]> {
    return this.platformRoleAssignmentRepository.findByIdentityId(identityId);
  }

  async getActiveAssignmentsByIdentity(identityId: string): Promise<PlatformIdentityRoleAssignment[]> {
    return this.platformRoleAssignmentRepository.findActiveByIdentityId(identityId);
  }

  async activateRole(input: ActivateRoleInput): Promise<PlatformIdentityRoleAssignment> {
    const assignments = await this.platformRoleAssignmentRepository.findActiveByIdentityId(input.identityId);
    const assignment = assignments.find(a => a.id === input.assignmentId);

    if (!assignment) {
      throw new NotFoundException('Role assignment not found');
    }

    if (!assignment.requiresJitActivation) {
      throw new Error('Only eligible role assignments can be activated');
    }

    assignment.activate(input.until);
    return this.platformRoleAssignmentRepository.save(assignment);
  }

  async deactivateRole(identityId: string, assignmentId: string, reason: string): Promise<PlatformIdentityRoleAssignment> {
    const assignments = await this.platformRoleAssignmentRepository.findActiveByIdentityId(identityId);
    const assignment = assignments.find(a => a.id === assignmentId);

    if (!assignment) {
      throw new NotFoundException('Role assignment not found');
    }

    assignment.deactivate(reason);
    return this.platformRoleAssignmentRepository.save(assignment);
  }

  async getPermissionsForIdentity(identityId: string): Promise<string[]> {
    const assignments = await this.getActiveAssignmentsByIdentity(identityId);
    const permissions = new Set<string>();

    for (const assignment of assignments) {
      const role = await this.getRoleById(assignment.roleId);
      for (const perm of role.permissions) {
        permissions.add(perm);
      }
    }

    return Array.from(permissions);
  }

  async hasPermission(identityId: string, permission: string): Promise<boolean> {
    const permissions = await this.getPermissionsForIdentity(identityId);
    const permissionPrefix = permission.split(':')[0] || '';
    return (permissions.includes('*') || permissions.includes(permission) ||
           (permissionPrefix.length > 0 && permissions.some(p => p.startsWith(permissionPrefix))));
  }
}
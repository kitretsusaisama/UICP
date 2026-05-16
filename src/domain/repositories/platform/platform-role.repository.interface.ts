import { PlatformRole } from '../../entities/platform/platform-role.entity';
import { PlatformIdentityRoleAssignment } from '../../entities/platform/platform-identity-role-assignment.entity';

export interface IPlatformRoleRepository {
  findById(id: string): Promise<PlatformRole | null>;
  findByType(type: string): Promise<PlatformRole | null>;
  findAll(): Promise<PlatformRole[]>;
  findSystemRoles(): Promise<PlatformRole[]>;
  save(entity: PlatformRole): Promise<PlatformRole>;
}

export interface IPlatformRoleAssignmentRepository {
  findById(id: string): Promise<PlatformIdentityRoleAssignment | null>;
  findByIdentityId(identityId: string): Promise<PlatformIdentityRoleAssignment[]>;
  findActiveByIdentityId(identityId: string): Promise<PlatformIdentityRoleAssignment[]>;
  findByRoleId(roleId: string): Promise<PlatformIdentityRoleAssignment[]>;
  findEligibleByIdentityId(identityId: string): Promise<PlatformIdentityRoleAssignment[]>;
  save(entity: PlatformIdentityRoleAssignment): Promise<PlatformIdentityRoleAssignment>;
  delete(id: string): Promise<void>;
}

export const PLATFORM_ROLE_REPOSITORY = 'PLATFORM_ROLE_REPOSITORY';
export const PLATFORM_ROLE_ASSIGNMENT_REPOSITORY = 'PLATFORM_ROLE_ASSIGNMENT_REPOSITORY';
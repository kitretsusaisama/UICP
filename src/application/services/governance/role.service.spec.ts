import { RoleService } from './role.service';
import { Role } from '../../../domain/entities/governance/role.entity';
import { NotFoundException, ForbiddenException } from '@nestjs/common';

describe('RoleService', () => {
  let roleService: RoleService;
  let roleRepoMock: any;
  let assignmentRepoMock: any;

  beforeEach(() => {
    roleRepoMock = {
      save: jest.fn(),
      findByIdAndTenant: jest.fn(),
      findByTenant: jest.fn(),
    };
    assignmentRepoMock = {
      save: jest.fn(),
      countByUserAndTenant: jest.fn(),
    };
    roleService = new RoleService(roleRepoMock, assignmentRepoMock);
  });

  it('should create a role successfully', async () => {
    const role = await roleService.createRole('tenant-1', 'admin', ['read', 'write'], 'desc');
    expect(role.name).toBe('admin');
    expect(role.permissions).toEqual(['read', 'write']);
    expect(role.version).toBe(1);
    expect(roleRepoMock.save).toHaveBeenCalledWith(role);
  });

  it('should prevent duplicate permissions on create', async () => {
    const role = await roleService.createRole('tenant-1', 'admin', ['read', 'read', 'write']);
    expect(role.permissions).toEqual(['read', 'write']);
  });

  it('should successfully assign a role', async () => {
    roleRepoMock.findByIdAndTenant.mockResolvedValue(new Role({ id: 'r-1', tenantId: 't-1', name: 'admin', permissions: [] }));
    assignmentRepoMock.countByUserAndTenant.mockResolvedValue(3);

    const assignment = await roleService.assignRole('t-1', 'admin-user', 'user-1', 'r-1');
    expect(assignment.userId).toBe('user-1');
    expect(assignment.roleId).toBe('r-1');
    expect(assignmentRepoMock.save).toHaveBeenCalledWith(assignment);
  });

  it('should reject assignment if role not found in tenant', async () => {
    roleRepoMock.findByIdAndTenant.mockResolvedValue(null);
    await expect(roleService.assignRole('t-1', 'admin-user', 'user-1', 'r-1')).rejects.toThrow(NotFoundException);
  });

  it('should reject assignment if max roles exceeded', async () => {
    roleRepoMock.findByIdAndTenant.mockResolvedValue(new Role({ id: 'r-1', tenantId: 't-1', name: 'admin', permissions: [] }));
    assignmentRepoMock.countByUserAndTenant.mockResolvedValue(10); // Max limit reached

    await expect(roleService.assignRole('t-1', 'admin-user', 'user-1', 'r-1')).rejects.toThrow(ForbiddenException);
  });
});

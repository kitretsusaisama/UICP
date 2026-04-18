import { RoleController } from './role.controller';
import { RoleService } from '../../../../application/services/governance/role.service';

describe('RoleController', () => {
  let controller: RoleController;
  let serviceMock: any;
  let reqMock: any;

  beforeEach(() => {
    serviceMock = {
      createRole: jest.fn().mockResolvedValue({ id: 'role-1' }),
      listRoles: jest.fn().mockResolvedValue([{ id: 'role-1' }]),
      assignRole: jest.fn().mockResolvedValue({ id: 'assign-1' }),
    };
    reqMock = { tenantId: 't-1', user: { sub: 'admin-1' } };
    controller = new RoleController(serviceMock as any);
  });

  it('should create a role', async () => {
    const result = await controller.createRole(reqMock, { name: 'admin', permissions: ['*'] });
    expect(result.success).toBe(true);
    expect(result.data.id).toBe('role-1');
  });

  it('should list roles', async () => {
    const result = await controller.listRoles(reqMock);
    expect(result.success).toBe(true);
    expect(result.data).toHaveLength(1);
  });

  it('should assign a role', async () => {
    const result = await controller.assignRole(reqMock, { userId: 'u-1', roleId: 'r-1' });
    expect(result.success).toBe(true);
    expect(result.data.id).toBe('assign-1');
  });
});

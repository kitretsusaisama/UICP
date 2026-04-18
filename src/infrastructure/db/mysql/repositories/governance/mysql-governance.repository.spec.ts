import { MysqlRoleRepository } from './mysql-role.repository';
import { MysqlRoleAssignmentRepository } from './mysql-role-assignment.repository';
import { MysqlPolicyRepository } from './mysql-policy.repository';
import { Role } from '../../../../../domain/entities/governance/role.entity';
import { RoleAssignment } from '../../../../../domain/entities/governance/role-assignment.entity';
import { Policy } from '../../../../../domain/entities/governance/policy.entity';

describe('MysqlGovernanceRepositories', () => {
  let poolMock: any;

  beforeEach(() => {
    poolMock = { execute: jest.fn() };
  });

  describe('MysqlRoleRepository', () => {
    it('should save a role', async () => {
      const repo = new MysqlRoleRepository(poolMock);
      const role = new Role({
        id: 'r-1',
        tenantId: 't-1',
        name: 'admin',
        permissions: ['read', 'write']
      });
      await repo.save(role);
      expect(poolMock.execute).toHaveBeenCalled();
    });
  });

  describe('MysqlRoleAssignmentRepository', () => {
    it('should count assignments', async () => {
      const repo = new MysqlRoleAssignmentRepository(poolMock);
      poolMock.execute.mockResolvedValue([[{ count: '5' }]]);
      const count = await repo.countByUserAndTenant('u-1', 't-1');
      expect(count).toBe(5);
    });
  });

  describe('MysqlPolicyRepository', () => {
    it('should save a policy', async () => {
      const repo = new MysqlPolicyRepository(poolMock);
      const policy = new Policy({
        id: 'p-1',
        tenantId: 't-1',
        name: 'Geo Policy',
        rules: {
          effect: 'allow',
          conditions: [{ field: 'geo', op: 'eq', value: 'US' }]
        }
      });
      await repo.save(policy);
      expect(poolMock.execute).toHaveBeenCalled();
    });
  });
});

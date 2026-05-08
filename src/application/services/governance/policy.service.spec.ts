import { PolicyService } from './policy.service';
import { Policy } from '../../../domain/entities/governance/policy.entity';
import { AbacPolicyEngine } from '../abac/abac-policy-engine';
import { BadRequestException, NotFoundException } from '@nestjs/common';

describe('PolicyService', () => {
  let policyService: PolicyService;
  let policyRepoMock: any;
  let abacEngineMock: any;

  beforeEach(() => {
    policyRepoMock = {
      save: jest.fn(),
      findByIdAndTenant: jest.fn(),
      findByTenant: jest.fn(),
    };

    abacEngineMock = {
      evaluateCondition: jest.fn(),
    };

    policyService = new PolicyService(policyRepoMock, abacEngineMock as unknown as AbacPolicyEngine);
  });

  it('should create a valid policy', async () => {
    const rules = {
      effect: 'allow' as const,
      conditions: [{ field: 'geo', op: 'eq' as const, value: 'US' }]
    };
    const policy = await policyService.createPolicy('tenant-1', 'geo-policy', rules, 'desc');

    expect(policy.name).toBe('geo-policy');
    expect(policy.rules.effect).toBe('allow');
    expect(policy.version).toBe(1);
    expect(policyRepoMock.save).toHaveBeenCalledWith(policy);
  });

  it('should reject policy creation with invalid operator', async () => {
    const rules = {
      effect: 'allow' as const,
      conditions: [{ field: 'geo', op: 'invalid_op' as any, value: 'US' }]
    };

    await expect(policyService.createPolicy('tenant-1', 'geo-policy', rules))
      .rejects.toThrow(BadRequestException);
  });

  it('should reject policy creation with invalid effect', async () => {
    const rules = {
      effect: 'invalid_effect' as any,
      conditions: [{ field: 'geo', op: 'eq' as const, value: 'US' }]
    };

    await expect(policyService.createPolicy('tenant-1', 'geo-policy', rules))
      .rejects.toThrow(BadRequestException);
  });

  it('should soft delete (deactivate) a policy', async () => {
    const policy = new Policy({
      id: 'p-1',
      tenantId: 'tenant-1',
      name: 'geo',
      rules: { effect: 'allow', conditions: [] },
      status: 'active',
      version: 1
    });

    policyRepoMock.findByIdAndTenant.mockResolvedValue(policy);

    await policyService.deletePolicy('p-1', 'tenant-1');
    expect(policy.status).toBe('inactive');
    expect(policy.version).toBe(2);
    expect(policyRepoMock.save).toHaveBeenCalledWith(policy);
  });

  it('should simulate a policy correctly using safe ABAC engine', async () => {
    const policy = new Policy({
      id: 'p-1',
      tenantId: 'tenant-1',
      name: 'geo',
      rules: {
        effect: 'allow',
        conditions: [{ field: 'env.geo', op: 'eq', value: 'US' }]
      },
    });

    policyRepoMock.findByIdAndTenant.mockResolvedValue(policy);

    // Matching context
    abacEngineMock.evaluateCondition.mockReturnValueOnce({ result: true, warnings: [] });
    const result1 = await policyService.testPolicy('p-1', 'tenant-1', { env: { geo: 'US' } });
    expect(result1.decision).toBe('ALLOW');
    expect(result1.reason).toContain('matched');
    expect(abacEngineMock.evaluateCondition).toHaveBeenCalledWith(
      JSON.stringify({"env.geo":{"$eq":"US"}}),
      { subject: {}, resource: {}, env: { geo: 'US' } }
    );

    // Failing context
    abacEngineMock.evaluateCondition.mockReturnValueOnce({ result: false, warnings: [] });
    const result2 = await policyService.testPolicy('p-1', 'tenant-1', { env: { geo: 'CA' } });
    expect(result2.decision).toBe('DENY');
    expect(result2.reason).toContain('failed to match');
  });

  it('should reject testing an inactive policy', async () => {
    const policy = new Policy({
      id: 'p-1',
      tenantId: 'tenant-1',
      name: 'geo',
      rules: { effect: 'allow', conditions: [] },
      status: 'inactive'
    });

    policyRepoMock.findByIdAndTenant.mockResolvedValue(policy);
    await expect(policyService.testPolicy('p-1', 'tenant-1', {})).rejects.toThrow(BadRequestException);
  });
});

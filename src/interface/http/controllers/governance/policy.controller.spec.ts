import { PolicyController } from './policy.controller';
import { EvaluationContext } from '../../../../domain/value-objects/abac-condition.vo';

describe('PolicyController', () => {
  let controller: PolicyController;
  let serviceMock: any;
  let reqMock: any;

  beforeEach(() => {
    serviceMock = {
      createPolicy: jest.fn().mockResolvedValue({ id: 'p-1' }),
      listPolicies: jest.fn().mockResolvedValue([{ id: 'p-1' }]),
      deletePolicy: jest.fn().mockResolvedValue(undefined),
      testPolicy: jest.fn().mockResolvedValue({ decision: 'ALLOW' }),
    };
    reqMock = { tenantId: 't-1' };
    controller = new PolicyController(serviceMock as any);
  });

  it('should create policy', async () => {
    const res = await controller.createPolicy(reqMock, { name: 'p1', rules: { effect: 'allow', conditions: [] }});
    expect(res.success).toBe(true);
    expect(res.data.id).toBe('p-1');
  });

  it('should list policies', async () => {
    const res = await controller.listPolicies(reqMock);
    expect(res.data).toHaveLength(1);
  });

  it('should delete policy', async () => {
    const res = await controller.deletePolicy(reqMock, 'p-1');
    expect(res.message).toBe('Policy deactivated successfully');
  });

  it('should test policy', async () => {
    const ctx: Partial<EvaluationContext> = { env: { geo: 'US' } };
    const res = await controller.testPolicy(reqMock, 'p-1', { context: ctx });
    expect(res.data.decision).toBe('ALLOW');
  });
});

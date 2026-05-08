import { Policy } from '../../entities/governance/policy.entity';

export const POLICY_REPOSITORY = 'POLICY_REPOSITORY';

export interface IPolicyRepository {
  save(policy: Policy): Promise<void>;
  findByIdAndTenant(id: string, tenantId: string): Promise<Policy | null>;
  findByTenant(tenantId: string): Promise<Policy[]>;
}

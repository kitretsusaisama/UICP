import { Injectable, Inject, NotFoundException, BadRequestException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { IPolicyRepository, POLICY_REPOSITORY } from '../../../domain/repositories/governance/policy.repository.interface';
import { Policy, PolicyRules } from '../../../domain/entities/governance/policy.entity';
import { AbacPolicyEngine } from '../abac/abac-policy-engine';
import { EvaluationContext } from '../../../domain/value-objects/abac-condition.vo';

@Injectable()
export class PolicyService {
  constructor(
    @Inject(POLICY_REPOSITORY) private readonly policyRepository: IPolicyRepository,
    private readonly abacEngine: AbacPolicyEngine,
  ) {}

  async createPolicy(tenantId: string, name: string, rules: PolicyRules, description?: string): Promise<Policy> {
    try {
      const policy = new Policy({
        id: uuidv4(),
        tenantId,
        name,
        description,
        rules,
      });

      await this.policyRepository.save(policy);
      return policy;
    } catch (e: any) {
      throw new BadRequestException(`Policy validation failed: ${e.message}`);
    }
  }

  async listPolicies(tenantId: string): Promise<Policy[]> {
    return this.policyRepository.findByTenant(tenantId);
  }

  async getPolicy(id: string, tenantId: string): Promise<Policy> {
    const policy = await this.policyRepository.findByIdAndTenant(id, tenantId);
    if (!policy) {
      throw new NotFoundException('Policy not found');
    }
    return policy;
  }

  async deletePolicy(id: string, tenantId: string): Promise<void> {
    const policy = await this.getPolicy(id, tenantId);
    policy.deactivate();
    await this.policyRepository.save(policy);
  }

  async testPolicy(id: string, tenantId: string, context: Partial<EvaluationContext>): Promise<{ decision: string, reason: string, trace: string[] }> {
    const policy = await this.getPolicy(id, tenantId);

    if (policy.status === 'inactive') {
      throw new BadRequestException('Cannot test an inactive policy');
    }

    // Convert the PolicyRules format into the DSL string format expected by AbacPolicyEngine
    const dslObject = policy.rules.conditions.reduce((acc, cond) => {
      acc[cond.field] = { [`$${cond.op}`]: cond.value };
      return acc;
    }, {} as Record<string, any>);

    const dslString = JSON.stringify(dslObject);

    // Provide default structured EvaluationContext if it's partial
    const fullContext: EvaluationContext = {
      subject: context.subject ?? {},
      resource: context.resource ?? {},
      env: context.env ?? {},
      ...context
    };

    // Call the safe, AST-based ABAC engine to evaluate the condition directly
    const result = this.abacEngine.evaluateCondition(dslString, fullContext);

    if (result.result) {
      return {
        decision: policy.rules.effect === 'allow' ? 'ALLOW' : 'DENY',
        reason: 'Context matched all policy conditions',
        trace: [`Matched policy: ${policy.name}`, ...policy.rules.conditions.map(c => `Condition passed: ${c.field} ${c.op} ${c.value}`)],
      };
    } else {
      return {
        decision: policy.rules.effect === 'allow' ? 'DENY' : 'ALLOW',
        reason: 'Context failed to match policy conditions',
        trace: [`Failed policy: ${policy.name}`, ...result.warnings],
      };
    }
  }
}

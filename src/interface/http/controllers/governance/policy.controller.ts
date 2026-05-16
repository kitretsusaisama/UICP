import { Controller, Post, Get, Delete, Body, Param, UseGuards, Req } from '@nestjs/common';
import { z } from 'zod';
import { PolicyService } from '../../../../application/services/governance/policy.service';
import { UnifiedAuthGuard } from '../../guards/unified-auth.guard';
import { TenantGuard } from '../../guards/tenant.guard';
import { PolicyRules } from '../../../../domain/entities/governance/policy.entity';
import { EvaluationContext } from '../../../../domain/value-objects/abac-condition.vo';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { createPolicyDto, testPolicyDto } from '../../dtos/governance/policy.dto';

@Controller('v1/policies')
@UseGuards(UnifiedAuthGuard, TenantGuard)
export class PolicyController {
  constructor(private readonly policyService: PolicyService) {}

  @Post()
  async createPolicy(
    @Req() req: any,
    @Body(new ZodValidationPipe(createPolicyDto)) body: z.infer<typeof createPolicyDto>,
  ) {
    const tenantId = req.tenantId;
    const policy = await this.policyService.createPolicy(tenantId, body.name, body.rules as PolicyRules, body.description);

    return {
      success: true,
      data: policy,
      meta: { version: 'v1' }
    };
  }

  @Get()
  async listPolicies(@Req() req: any) {
    const tenantId = req.tenantId;
    const policies = await this.policyService.listPolicies(tenantId);

    return {
      success: true,
      data: policies,
      meta: { version: 'v1' }
    };
  }

  @Delete(':id')
  async deletePolicy(@Req() req: any, @Param('id') id: string) {
    const tenantId = req.tenantId;
    await this.policyService.deletePolicy(id, tenantId);

    return {
      success: true,
      data: null,
      message: 'Policy deactivated successfully',
      meta: { version: 'v1' }
    };
  }

  @Post(':id/test')
  async testPolicy(
    @Req() req: any,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(testPolicyDto)) body: z.infer<typeof testPolicyDto>,
  ) {
    const tenantId = req.tenantId;
    const result = await this.policyService.testPolicy(id, tenantId, body.context as Partial<EvaluationContext>);

    return {
      success: true,
      data: result,
      meta: { version: 'v1' }
    };
  }
}

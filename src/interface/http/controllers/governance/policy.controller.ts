import { Controller, Post, Get, Delete, Body, Param, UseGuards, Req } from '@nestjs/common';
import { PolicyService } from '../../../../application/services/governance/policy.service';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { TenantGuard } from '../../guards/tenant.guard';
import { PolicyRules } from '../../../../domain/entities/governance/policy.entity';
import { EvaluationContext } from '../../../../domain/value-objects/abac-condition.vo';

@Controller('v1/policies')
@UseGuards(JwtAuthGuard, TenantGuard)
export class PolicyController {
  constructor(private readonly policyService: PolicyService) {}

  @Post()
  async createPolicy(@Req() req: any, @Body() body: { name: string; rules: PolicyRules; description?: string }) {
    const tenantId = req.tenantId;
    const policy = await this.policyService.createPolicy(tenantId, body.name, body.rules, body.description);

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
  async testPolicy(@Req() req: any, @Param('id') id: string, @Body() body: { context: Partial<EvaluationContext> }) {
    const tenantId = req.tenantId;
    const result = await this.policyService.testPolicy(id, tenantId, body.context);

    return {
      success: true,
      data: result,
      meta: { version: 'v1' }
    };
  }
}

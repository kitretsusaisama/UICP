import { Governance } from '../../../../src/infrastructure/governance/decorators/governance.decorator';
import { GovernanceGuard } from '../../../../src/infrastructure/governance/guards/governance.guard';
import { Controller, Post, Get, Param, Body, UseGuards, Req, UseGuards } from '@nestjs/common';
import { DomainService } from '../../../../application/services/platform/domain.service';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { TenantGuard } from '../../guards/tenant.guard';

@Controller('v1/domains')
@UseGuards(JwtAuthGuard, TenantGuard)
export class DomainController {
  constructor(private readonly domainService: DomainService) {}

  @Post()
  async registerDomain(@Req() req: any, @Body('domainName') domainName: string) {
    const tenantId = req.tenantId;
    const domain = await this.domainService.registerDomain(tenantId, domainName);
    return {
      success: true,
      data: domain,
      meta: { version: 'v1' }
    };
  }

  @Get()
  async listDomains(@Req() req: any) {
    const tenantId = req.tenantId;
    const domains = await this.domainService.listDomains(tenantId);
    return {
      success: true,
      data: domains,
      meta: { version: 'v1' }
    };
  }

  @Post(':id/verify')
  async verifyDomain(@Req() req: any, @Param('id') id: string) {
    const tenantId = req.tenantId;
    const domain = await this.domainService.verifyDomain(id, tenantId);
    return {
      success: true,
      data: domain,
      meta: { version: 'v1' }
    };
  }
}

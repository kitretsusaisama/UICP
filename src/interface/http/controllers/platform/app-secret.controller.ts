import { Governance } from '../../../../src/infrastructure/governance/decorators/governance.decorator';
import { GovernanceGuard } from '../../../../src/infrastructure/governance/guards/governance.guard';
import { Controller, Post, Get, Put, Param, Body, UseGuards, Req, UseGuards } from '@nestjs/common';
import { AppSecretService } from '../../../../application/services/platform/app-secret.service';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { TenantGuard } from '../../guards/tenant.guard';

@Controller('v1/apps/:appId/secrets')
@UseGuards(JwtAuthGuard, TenantGuard)
export class AppSecretController {
  constructor(private readonly appSecretService: AppSecretService) {}

  @Post()
  async generateSecret(@Req() req: any, @Param('appId') appId: string) {
    const tenantId = req.tenantId;
    const result = await this.appSecretService.generateSecret(appId, tenantId);
    return {
      success: true,
      data: {
        secretKey: result.secretKey,
        secretHash: result.secretHash,
        warning: 'This secret will only be shown once. Please store it securely.'
      },
      meta: { version: 'v1' }
    };
  }

  @Get()
  async listSecrets(@Req() req: any, @Param('appId') appId: string) {
    const tenantId = req.tenantId;
    const secrets = await this.appSecretService.listSecrets(appId, tenantId);
    return {
      success: true,
      data: secrets,
      meta: { version: 'v1' }
    };
  }

  @Post(':secretHash/deprecate')
  async deprecateSecret(
    @Req() req: any,
    @Param('appId') appId: string,
    @Param('secretHash') secretHash: string,
    @Body('gracePeriodSeconds') gracePeriodSeconds?: number
  ) {
    const tenantId = req.tenantId;
    await this.appSecretService.deprecateSecret(appId, tenantId, secretHash, gracePeriodSeconds);
    return {
      success: true,
      data: null,
      meta: { version: 'v1' }
    };
  }

  @Post(':secretHash/revoke')
  async revokeSecret(
    @Req() req: any,
    @Param('appId') appId: string,
    @Param('secretHash') secretHash: string
  ) {
    const tenantId = req.tenantId;
    await this.appSecretService.revokeSecret(appId, tenantId, secretHash);
    return {
      success: true,
      data: null,
      meta: { version: 'v1' }
    };
  }
}

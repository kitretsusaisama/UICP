import { Governance } from '../../../../src/infrastructure/governance/decorators/governance.decorator';
import { GovernanceGuard } from '../../../../src/infrastructure/governance/guards/governance.guard';
import { Controller, Post, Get, Put, Param, Body, UseGuards, Req, UseGuards } from '@nestjs/common';
import { AppService } from '../../../../application/services/platform/app.service';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { TenantGuard } from '../../guards/tenant.guard';
import { AppType } from '../../../../domain/entities/platform/app.entity';

interface CreateAppDto {
  name: string;
  type: AppType;
  redirectUris?: string[];
  allowedOrigins?: string[];
}

interface UpdateAppMetadataDto {
  redirectUris: string[];
  allowedOrigins: string[];
}

@Controller('v1/apps')
@UseGuards(JwtAuthGuard, TenantGuard)
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post()
  async registerApp(@Req() req: any, @Body() body: CreateAppDto) {
    const tenantId = req.tenantId;
    const app = await this.appService.registerApp(
      tenantId,
      body.name,
      body.type,
      body.redirectUris ?? [],
      body.allowedOrigins ?? []
    );
    return {
      success: true,
      data: app,
      meta: { version: 'v1' }
    };
  }

  @Get()
  async listApps(@Req() req: any) {
    const tenantId = req.tenantId;
    const apps = await this.appService.listApps(tenantId);
    return {
      success: true,
      data: apps,
      meta: { version: 'v1' }
    };
  }

  @Get(':id')
  async getApp(@Req() req: any, @Param('id') id: string) {
    const tenantId = req.tenantId;
    const app = await this.appService.getApp(id, tenantId);
    return {
      success: true,
      data: app,
      meta: { version: 'v1' }
    };
  }

  @Put(':id/metadata')
  async updateAppMetadata(
    @Req() req: any,
    @Param('id') id: string,
    @Body() body: UpdateAppMetadataDto
  ) {
    const tenantId = req.tenantId;
    const app = await this.appService.updateAppMetadata(
      id,
      tenantId,
      body.redirectUris,
      body.allowedOrigins
    );
    return {
      success: true,
      data: app,
      meta: { version: 'v1' }
    };
  }
}

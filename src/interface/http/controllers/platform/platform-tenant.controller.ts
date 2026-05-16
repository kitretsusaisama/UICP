import { Controller, Post, Get, Patch, Delete, Body, Param, UseGuards, Query, HttpCode } from '@nestjs/common';
import { PlatformTenantService } from '../../../../application/services/platform/platform-tenant.service';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';

const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1/tenants')
@UseGuards(PlatformApiKeyGuard)
export class PlatformTenantController {
  constructor(private readonly tenantService: PlatformTenantService) {}

  @Post()
  @HttpCode(201)
  @RequireScopes('tenant:create')
  async createTenant(@Body() body: { name: string; domain?: string; plan?: string; quota?: any; metadata?: any }) {
    const tenant = await this.tenantService.create({
      name: body.name,
      domain: body.domain,
      plan: body.plan,
      quota: body.quota,
      metadata: body.metadata
    });
    return { data: tenant };
  }

  @Get()
  @RequireScopes('tenant:read')
  async listTenants(@Query() query: { status?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.tenantService.list({
      status: query.status,
      limit,
      offset
    });
    return {
      data: result.tenants,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/tenants?limit=${limit}&offset=${offset}` }
    };
  }

  @Get(':id')
  @RequireScopes('tenant:read')
  async getTenant(@Param('id') id: string) {
    const tenant = await this.tenantService.getById(id);
    return { data: tenant };
  }

  @Patch(':id')
  @RequireScopes('tenant:write')
  async updateTenant(@Param('id') id: string, @Body() body: { name?: string; domain?: string; plan?: string; quota?: any; metadata?: any }) {
    const tenant = await this.tenantService.update(id, body);
    return { data: tenant };
  }

  @Patch(':id/status')
  @RequireScopes('tenant:suspend')
  async updateTenantStatus(@Param('id') id: string, @Body() body: { status: 'suspended' | 'active'; reason?: string }) {
    const reason = body.reason || '';
    const tenant = body.status === 'suspended'
      ? await this.tenantService.suspend(id, reason)
      : await this.tenantService.reactivate(id);
    return { data: tenant };
  }

  @Delete(':id')
  @HttpCode(204)
  @RequireScopes('tenant:delete')
  async deleteTenant(@Param('id') id: string) {
    await this.tenantService.delete(id);
    return { data: { id, status: 'deactivated' } };
  }

  @Post(':id/migrate')
  @RequireScopes('tenant:migrate')
  async migrateTenant(@Param('id') id: string, @Body() body: { targetRegion: string }) {
    const result = await this.tenantService.migrate(id, body.targetRegion);
    return { data: result };
  }

  @Post(':id/clone')
  @HttpCode(201)
  @RequireScopes('tenant:create')
  async cloneTenant(@Param('id') id: string, @Body() body: { newName: string }) {
    const tenant = await this.tenantService.clone(id, body.newName);
    return { data: { id: tenant.id, clonedFrom: id, name: tenant.name } };
  }

  @Get(':id/usage')
  @RequireScopes('usage:read')
  async getTenantUsage(@Param('id') id: string) {
    const usage = await this.tenantService.getUsage(id);
    return { data: usage };
  }

  @Post(':id/quota')
  @RequireScopes('quota:write')
  async setTenantQuota(@Param('id') id: string, @Body() body: { apiCalls: number; storage: number; users: number; domains: number }) {
    const tenant = await this.tenantService.setQuota(id, body);
    return { data: { tenantId: id, quota: tenant.quota } };
  }
}
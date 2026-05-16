import { Controller, Post, Get, Patch, Body, Param, UseGuards, Req, HttpCode, Query } from '@nestjs/common';
import { PlatformIdentityService } from '../../../../application/services/platform/platform-identity.service';
import { PlatformApiKeyService } from '../../../../application/services/platform/platform-api-key.service';
import { PlatformRoleService } from '../../../../application/services/platform/platform-role.service';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';

const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1')
@UseGuards(PlatformApiKeyGuard)
export class PlatformGovernanceController {
  constructor(
    private readonly identityService: PlatformIdentityService,
    private readonly apiKeyService: PlatformApiKeyService,
    private readonly roleService: PlatformRoleService,
  ) {}

  @Post('identities')
  @HttpCode(201)
  @RequireScopes('identity:write')
  async createIdentity(@Body() body: any) {
    const identity = await this.identityService.create({ email: body.email, displayName: body.displayName, passwordHash: body.passwordHash });
    return { data: identity.toResponse() };
  }

  @Get('identities')
  @RequireScopes('identity:read')
  async listIdentities(@Query('limit') limit?: string, @Query('offset') offset?: string) {
    const identities = await this.identityService.listAll();
    const total = identities.length;
    const perPage = parseInt(limit || '50') || 50;
    const offsetVal = parseInt(offset || '0') || 0;
    return {
      data: identities.map(i => i.toResponse()),
      meta: { total, page: 1, per_page: perPage, total_pages: Math.ceil(total / perPage) },
      links: { self: `/platform/v1/identities?limit=${perPage}&offset=${offsetVal}` }
    };
  }

  @Get('identities/:id')
  @RequireScopes('identity:read')
  async getIdentity(@Param('id') id: string) {
    const identity = await this.identityService.getById(id);
    return { data: identity.toResponse() };
  }

  @Patch('identities/:id/status')
  @RequireScopes('identity:write')
  async updateIdentityStatus(@Param('id') id: string, @Body() body: { status: 'suspended' | 'active'; reason?: string }) {
    const reason = body.reason || '';
    const identity = body.status === 'suspended'
      ? await this.identityService.suspend(id, reason)
      : await this.identityService.reactivate(id);
    return { data: identity.toResponse() };
  }

  @Post('identities/:id/api-keys')
  @HttpCode(201)
  @RequireScopes('identity:write')
  async createApiKey(@Param('id') id: string, @Body() body: any) {
    const result = await this.apiKeyService.create({ platformIdentityId: id, name: body.name, scopes: body.scopes, ipAllowlist: body.ipAllowlist, rateLimit: body.rateLimit, expiresInDays: body.expiresInDays, env: body.env });
    return { data: { publishableKey: result.publishableKey, secretKey: result.secretKey, apiKey: result.apiKey.toResponse() } };
  }

  @Get('identities/:id/api-keys')
  @RequireScopes('identity:read')
  async listApiKeys(@Param('id') id: string) {
    const keys = await this.apiKeyService.listByIdentity(id);
    return { data: keys.map(k => k.toResponse()) };
  }

  @Get('roles')
  @RequireScopes('role:read')
  async listRoles() {
    const roles = await this.roleService.listAllRoles();
    return { data: roles.map(r => r.toResponse()) };
  }

  @Get('roles/system')
  @RequireScopes('role:read')
  async listSystemRoles() {
    const roles = await this.roleService.listSystemRoles();
    return { data: roles.map(r => r.toResponse()) };
  }

  @Post('roles/bootstrap')
  @HttpCode(201)
  @RequireScopes('role:write')
  async bootstrapRoles() {
    const roles = await this.roleService.bootstrapSystemRoles();
    return { data: roles.map(r => r.toResponse()) };
  }

  @Post('identities/:id/roles')
  @HttpCode(201)
  @RequireScopes('role:assign')
  async assignRole(@Param('id') identityId: string, @Body() body: any, @Req() req: any) {
    const assignment = await this.roleService.assignRole({ platformIdentityId: identityId, roleId: body.roleId, roleType: body.roleType, assignmentType: body.assignmentType, assignedBy: req.platformId, justification: body.justification });
    return { data: assignment.toResponse() };
  }

  @Get('identities/:id/roles')
  @RequireScopes('role:read')
  async getIdentityRoles(@Param('id') id: string) {
    const assignments = await this.roleService.getActiveAssignmentsByIdentity(id);
    return { data: assignments.map(a => a.toResponse()) };
  }

  @Post('identities/:id/roles/activate')
  @RequireScopes('jit:activate')
  async activateRole(@Param('id') identityId: string, @Body() body: any) {
    const assignment = await this.roleService.activateRole({ identityId, assignmentId: body.assignmentId, until: body.until ? new Date(body.until) : undefined });
    return { data: assignment.toResponse() };
  }

  @Get('identities/:id/permissions')
  @RequireScopes('role:read')
  async getPermissions(@Param('id') id: string) {
    const permissions = await this.roleService.getPermissionsForIdentity(id);
    return { data: { permissions } };
  }
}
import { Controller, Post, Get, Body, Param, UseGuards, Req } from '@nestjs/common';
import { RoleService } from '../../../../application/services/governance/role.service';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { TenantGuard } from '../../guards/tenant.guard';

@Controller('v1/roles')
@UseGuards(JwtAuthGuard, TenantGuard)
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Post()
  async createRole(@Req() req: any, @Body() body: { name: string; permissions: string[]; description?: string }) {
    const tenantId = req.tenantId;
    const role = await this.roleService.createRole(tenantId, body.name, body.permissions, body.description);

    return {
      success: true,
      data: role,
      meta: { version: 'v1' }
    };
  }

  @Get()
  async listRoles(@Req() req: any) {
    const tenantId = req.tenantId;
    const roles = await this.roleService.listRoles(tenantId);
    return {
      success: true,
      data: roles,
      meta: { version: 'v1' }
    };
  }

  @Post('assign')
  async assignRole(@Req() req: any, @Body() body: { userId: string; roleId: string; expiresAt?: string }) {
    const tenantId = req.tenantId;
    const assignedBy = req.user.sub;

    const assignment = await this.roleService.assignRole(
      tenantId,
      assignedBy,
      body.userId,
      body.roleId,
      body.expiresAt
    );

    return {
      success: true,
      data: assignment,
      meta: { version: 'v1' }
    };
  }
}

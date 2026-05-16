import { Controller, Post, Get, Body, Param, UseGuards, Req } from '@nestjs/common';
import { z } from 'zod';
import { RoleService } from '../../../../application/services/governance/role.service';
import { UnifiedAuthGuard } from '../../guards/unified-auth.guard';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { createRoleDto, assignRoleDto } from '../../dtos/governance/role.dto';

@Controller('v1/roles')
@UseGuards(UnifiedAuthGuard)
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Post()
  async createRole(
    @Req() req: any,
    @Body(new ZodValidationPipe(createRoleDto)) body: z.infer<typeof createRoleDto>,
  ) {
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
  async assignRole(
    @Req() req: any,
    @Body(new ZodValidationPipe(assignRoleDto)) body: z.infer<typeof assignRoleDto>,
  ) {
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

import { Controller, Post, Get, Body, Param, UseGuards, HttpCode, Query, Req } from '@nestjs/common';
import { PlatformApprovalService } from '../../../../application/services/platform/platform-approval.service';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';

const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1/approvals')
@UseGuards(PlatformApiKeyGuard)
export class PlatformApprovalController {
  constructor(private readonly approvalService: PlatformApprovalService) {}

  @Get()
  @RequireScopes('approval:read')
  async listApprovals(@Query() query: { tenantId?: string; status?: string; resourceType?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.approvalService.list({
      tenantId: query.tenantId,
      status: query.status,
      resourceType: query.resourceType,
      limit,
      offset
    });
    return {
      data: result.requests,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/approvals?limit=${limit}&offset=${offset}` }
    };
  }

  @Post('request')
  @HttpCode(201)
  @RequireScopes('approval:request')
  async requestApproval(@Body() body: { requesterId: string; requesterTenantId: string; resourceType: string; resourceId: string; action: string; justification: string; priority?: string; approverIds: string[]; expiresInHours?: number; metadata?: any }) {
    const request = await this.approvalService.requestApproval({
      requesterId: body.requesterId,
      requesterTenantId: body.requesterTenantId,
      resourceType: body.resourceType,
      resourceId: body.resourceId,
      action: body.action,
      justification: body.justification,
      priority: body.priority as any,
      approverIds: body.approverIds,
      expiresInHours: body.expiresInHours,
      metadata: body.metadata
    });
    return { data: request };
  }

  @Post(':id/approve')
  @RequireScopes('approval:approve')
  async approve(@Param('id') id: string, @Body() body: { comments?: string }, @Req() req: any) {
    const request = await this.approvalService.approve(id, req.platformId, body.comments);
    return { data: request };
  }

  @Post(':id/reject')
  @RequireScopes('approval:reject')
  async reject(@Param('id') id: string, @Body() body: { reason: string }, @Req() req: any) {
    const request = await this.approvalService.reject(id, req.platformId, body.reason);
    return { data: request };
  }

  @Post(':id/escalate')
  @RequireScopes('approval:escalate')
  async escalate(@Param('id') id: string, @Body() body: { reason: string }, @Req() req: any) {
    const request = await this.approvalService.escalate(id, req.platformId, body.reason);
    return { data: request };
  }

  @Get('pending')
  @RequireScopes('approval:read')
  async getPendingForApprover(@Req() req: any) {
    const requests = await this.approvalService.getPendingForApprover(req.platformId);
    return { data: requests };
  }
}
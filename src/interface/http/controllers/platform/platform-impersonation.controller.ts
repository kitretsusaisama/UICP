import { Controller, Post, Get, Delete, Body, Param, UseGuards, HttpCode, Query, Req } from '@nestjs/common';
import { PlatformImpersonationService } from '../../../../application/services/platform/platform-impersonation.service';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';

const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1/impersonate')
@UseGuards(PlatformApiKeyGuard)
export class PlatformImpersonationController {
  constructor(private readonly impersonationService: PlatformImpersonationService) {}

  @Post('sessions')
  @HttpCode(201)
  @RequireScopes('impersonate:request')
  async startImpersonation(@Body() body: { platformIdentityId: string; tenantId: string; targetIdentityId: string; reason: string }, @Req() req: any) {
    const session = await this.impersonationService.start({
      platformIdentityId: body.platformIdentityId,
      tenantId: body.tenantId,
      targetIdentityId: body.targetIdentityId,
      reason: body.reason,
      ipAddress: req.ip || req.connection?.remoteAddress,
      userAgent: req.headers['user-agent']
    });
    return { data: session };
  }

  @Delete('sessions/:id')
  @HttpCode(204)
  @RequireScopes('impersonate:request')
  async endImpersonation(@Param('id') sessionId: string, @Body() body: { reason?: string }) {
    const session = await this.impersonationService.end(sessionId, body.reason);
    return { data: session };
  }

  @Get('sessions')
  @RequireScopes('impersonate:read')
  async listSessions(@Query() query: { tenantId?: string; status?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.impersonationService.list({
      tenantId: query.tenantId,
      status: query.status,
      limit,
      offset
    });
    return {
      data: result.sessions,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/impersonate/sessions?limit=${limit}&offset=${offset}` }
    };
  }

  @Get('sessions/:id')
  @RequireScopes('impersonate:read')
  async getSession(@Param('id') id: string) {
    const session = await this.impersonationService.getById(id);
    return { data: session };
  }

  @Post('sessions/:id/approve')
  @RequireScopes('impersonate:approve')
  async approve(@Param('id') sessionId: string, @Req() req: any) {
    const session = await this.impersonationService.approve(sessionId, req.platformId);
    return { data: session };
  }

  @Post('sessions/:id/reject')
  @RequireScopes('impersonate:approve')
  async reject(@Param('id') sessionId: string, @Body() body: { reason: string }) {
    const session = await this.impersonationService.end(sessionId, body.reason);
    return { data: session };
  }
}
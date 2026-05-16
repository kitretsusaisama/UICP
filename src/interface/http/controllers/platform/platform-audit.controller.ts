import { Controller, Post, Get, Body, Param, UseGuards, Query, HttpCode } from '@nestjs/common';
import { PlatformAuditService } from '../../../../application/services/platform/platform-audit.service';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';

const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1')
@UseGuards(PlatformApiKeyGuard)
export class PlatformAuditController {
  constructor(private readonly auditService: PlatformAuditService) {}

  @Get('audit')
  @RequireScopes('audit:read')
  async listAudit(@Query() query: { tenantId?: string; actorId?: string; resourceType?: string; action?: string; startDate?: string; endDate?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.auditService.listAudit({
      tenantId: query.tenantId,
      actorId: query.actorId,
      resourceType: query.resourceType,
      action: query.action,
      startDate: query.startDate ? new Date(query.startDate) : undefined,
      endDate: query.endDate ? new Date(query.endDate) : undefined,
      limit,
      offset
    });
    return {
      data: result.logs,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/audit?limit=${limit}&offset=${offset}` }
    };
  }

  @Get('audit/:id')
  @RequireScopes('audit:read')
  async getAuditById(@Param('id') id: string) {
    const log = await this.auditService.getAuditById(id);
    return { data: log };
  }

  @Get('audit/export')
  @RequireScopes('audit:export')
  async exportAudit(@Query() query: { tenantId?: string; startDate: string; endDate: string; format?: string }) {
    const result = await this.auditService.exportAudit({
      tenantId: query.tenantId,
      startDate: new Date(query.startDate),
      endDate: new Date(query.endDate),
      format: query.format
    });
    return { data: result };
  }

  @Get('sign-ins')
  @RequireScopes('signin:read')
  async listSignIns(@Query() query: { tenantId?: string; identityId?: string; success?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.auditService.listSignIns({
      tenantId: query.tenantId,
      identityId: query.identityId,
      success: query.success === 'true',
      limit,
      offset
    });
    return {
      data: result.logs,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/sign-ins?limit=${limit}&offset=${offset}` }
    };
  }

  @Get('compliance/reports')
  @RequireScopes('compliance:read')
  async listReports(@Query() query: { tenantId?: string; type?: string; status?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.auditService.listReports({
      tenantId: query.tenantId,
      type: query.type,
      status: query.status,
      limit,
      offset
    });
    return {
      data: result.reports,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/compliance/reports?limit=${limit}&offset=${offset}` }
    };
  }

  @Get('compliance/reports/:id')
  @RequireScopes('compliance:read')
  async getReport(@Param('id') id: string) {
    const report = await this.auditService.getReportById(id);
    return { data: report };
  }

  @Post('compliance/reports')
  @HttpCode(201)
  @RequireScopes('report:generate')
  async genReport(@Body() body: { name: string; type: string; tenantId?: string; format?: string; generatedBy: string }) {
    const report = await this.auditService.generateReport({
      name: body.name,
      type: body.type,
      tenantId: body.tenantId,
      format: body.format,
      generatedBy: body.generatedBy
    });
    return { data: report };
  }
}
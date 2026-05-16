import { Controller, Post, Get, Patch, Body, Param, UseGuards, Query, HttpCode } from '@nestjs/common';
import { PlatformSecurityService } from '../../../../application/services/platform/platform-security.service';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';

const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1/security')
@UseGuards(PlatformApiKeyGuard)
export class PlatformSecurityController {
  constructor(private readonly securityService: PlatformSecurityService) {}

  @Get('incidents')
  @RequireScopes('security:read')
  async listIncidents(@Query() query: { tenantId?: string; status?: string; severity?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.securityService.listIncidents({
      tenantId: query.tenantId,
      status: query.status,
      severity: query.severity,
      limit,
      offset
    });
    return {
      data: result.incidents,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/security/incidents?limit=${limit}&offset=${offset}` }
    };
  }

  @Post('incidents')
  @HttpCode(201)
  @RequireScopes('security:write')
  async createIncident(@Body() body: { tenantId?: string; severity: string; type: string; title: string; description: string; source: string; ipAddress?: string; userAgent?: string; affectedResources?: string[]; indicators?: any }) {
    const incident = await this.securityService.createIncident({
      tenantId: body.tenantId,
      severity: body.severity as any,
      type: body.type,
      title: body.title,
      description: body.description,
      source: body.source,
      ipAddress: body.ipAddress,
      userAgent: body.userAgent,
      affectedResources: body.affectedResources,
      indicators: body.indicators
    });
    return { data: incident };
  }

  @Patch('incidents/:id')
  @RequireScopes('security:write')
  async updateIncident(@Param('id') id: string, @Body() body: { status: string; mitigation?: string; resolvedBy?: string }) {
    const incident = await this.securityService.updateIncidentStatus(id, body.status, body.mitigation, body.resolvedBy);
    return { data: incident };
  }

  @Get('threat-intel')
  @RequireScopes('threat-intel:read')
  async getThreatIntel(@Query() query: { type?: string; threatLevel?: string; tags?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.securityService.listThreats({
      type: query.type,
      threatLevel: query.threatLevel,
      tags: query.tags,
      limit,
      offset
    });
    return {
      data: result.threats,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/security/threat-intel?limit=${limit}&offset=${offset}` }
    };
  }

  @Post('threat-intel')
  @HttpCode(201)
  @RequireScopes('threat-intel:write')
  async addThreatIndicator(@Body() body: { indicator: string; type: string; threatLevel: string; source: string; description: string; tags?: string[]; metadata?: any }) {
    const threat = await this.securityService.addThreatIndicator({
      indicator: body.indicator,
      type: body.type as any,
      threatLevel: body.threatLevel as any,
      source: body.source,
      description: body.description,
      tags: body.tags,
      metadata: body.metadata
    });
    return { data: threat };
  }

  @Post('threat-intel/check')
  @RequireScopes('threat-intel:read')
  async checkThreat(@Body() body: { indicator: string; type: string }) {
    const threat = await this.securityService.checkThreat(body.indicator, body.type);
    return { data: threat };
  }

  @Get('risk-scores')
  @RequireScopes('risk-score:read')
  async getRiskScores(@Query() query: { tenantId: string }) {
    const analysis = await this.securityService.analyzeRisk(query.tenantId);
    return { data: analysis };
  }

  @Get('anomalies')
  @RequireScopes('anomaly:read')
  async getAnomalies(@Query() query: { tenantId: string }) {
    const anomalies = await this.securityService.getAnomalies(query.tenantId);
    return { data: anomalies };
  }

  @Post('analyze')
  @RequireScopes('security:write')
  async analyze(@Body() body: { tenantId: string }) {
    const analysis = await this.securityService.analyzeRisk(body.tenantId);
    return { data: analysis };
  }

  @Post('vulnerability-scan')
  @HttpCode(201)
  @RequireScopes('vulnerability:write')
  async runVulnerabilityScan(@Body() body: { tenantId: string }) {
    const result = await this.securityService.runVulnerabilityScan(body.tenantId);
    return { data: result };
  }

  @Get('vulnerability-scan/:scanId')
  @RequireScopes('vulnerability:read')
  async getVulnerabilityScanResults(@Param('scanId') scanId: string) {
    const result = await this.securityService.getVulnerabilityScanResults(scanId);
    return { data: result };
  }

  @Post('incidents/:id/respond')
  @RequireScopes('security:write')
  async respond(@Param('id') id: string, @Body() body: { status: string; mitigation?: string }) {
    const incident = await this.securityService.updateIncidentStatus(id, body.status, body.mitigation);
    return { data: { responseId: id, incident } };
  }
}
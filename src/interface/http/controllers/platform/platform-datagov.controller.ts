import { Controller, Post, Get, Patch, Body, Param, UseGuards, Query, HttpCode } from '@nestjs/common';
import { PlatformDataGovService } from '../../../../application/services/platform/platform-datagov.service';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';

const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1')
@UseGuards(PlatformApiKeyGuard)
export class PlatformDataGovController {
  constructor(private readonly dataGovService: PlatformDataGovService) {}

  @Get('consents')
  @RequireScopes('consent:read')
  async listConsents(@Query() query: { tenantId: string; granted?: string; consentType?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.dataGovService.listConsents(query.tenantId, {
      granted: query.granted === 'true',
      consentType: query.consentType,
      limit,
      offset
    });
    return {
      data: result.consents,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/consents?limit=${limit}&offset=${offset}` }
    };
  }

  @Post('consents')
  @HttpCode(201)
  @RequireScopes('consent:manage')
  async recordConsent(@Body() body: { identityId: string; tenantId: string; consentType: string; granted: boolean; purpose: string; version: string; source?: string; metadata?: any }) {
    const consent = await this.dataGovService.recordConsent({
      identityId: body.identityId,
      tenantId: body.tenantId,
      consentType: body.consentType,
      granted: body.granted,
      purpose: body.purpose,
      version: body.version,
      source: body.source,
      metadata: body.metadata
    });
    return { data: consent };
  }

  @Get('consents/:identityId')
  @RequireScopes('consent:read')
  async getConsents(@Param('identityId') id: string, @Query() query: { tenantId?: string }) {
    const consents = await this.dataGovService.getConsentsByIdentity(id, query.tenantId);
    return { data: consents };
  }

  @Post('consents/:identityId/withdraw')
  @RequireScopes('consent:manage')
  async withdrawConsent(@Param('identityId') id: string, @Body() body: { consentType: string }) {
    const consent = await this.dataGovService.withdrawConsent(id, body.consentType);
    return { data: { status: 'withdrawn', consent } };
  }

  @Get('retention/policies')
  @RequireScopes('retention:read')
  async listRetentionPolicies(@Query() query: { tenantId: string }) {
    const policies = await this.dataGovService.listRetentionPolicies(query.tenantId);
    return { data: policies };
  }

  @Post('retention/policies')
  @HttpCode(201)
  @RequireScopes('retention:write')
  async createRetentionPolicy(@Body() body: { tenantId: string; name: string; dataType: string; retentionDays: number; action: string; conditions?: any; createdBy: string }) {
    const policy = await this.dataGovService.createRetentionPolicy({
      tenantId: body.tenantId,
      name: body.name,
      dataType: body.dataType,
      retentionDays: body.retentionDays,
      action: body.action as any,
      conditions: body.conditions,
      createdBy: body.createdBy
    });
    return { data: policy };
  }

  @Patch('retention/policies/:id')
  @RequireScopes('retention:write')
  async updateRetentionPolicy(@Param('id') id: string, @Body() body: { name?: string; retentionDays?: number; action?: 'delete' | 'archive' | 'anonymize'; conditions?: any }) {
    const policy = await this.dataGovService.updateRetentionPolicy(id, body);
    return { data: policy };
  }

  @Post('retention/purge')
  @RequireScopes('retention:write')
  async triggerPurge(@Body() body: { tenantId: string; policyId?: string }) {
    const result = await this.dataGovService.triggerPurge(body.tenantId, body.policyId);
    return { data: result };
  }

  @Post('dsar/requests')
  @HttpCode(201)
  @RequireScopes('dsar:request')
  async requestDSAR(@Body() body: { requesterEmail: string; tenantId: string; requestType: string; identityId?: string; metadata?: any }) {
    const request = await this.dataGovService.createDSARRequest({
      requesterEmail: body.requesterEmail,
      tenantId: body.tenantId,
      requestType: body.requestType as any,
      identityId: body.identityId,
      metadata: body.metadata
    });
    return { data: request };
  }

  @Get('dsar/requests')
  @RequireScopes('dsar:read')
  async listDSARRequests(@Query() query: { tenantId: string; status?: string; requestType?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.dataGovService.listDSARRequests(query.tenantId, {
      status: query.status,
      requestType: query.requestType,
      limit,
      offset
    });
    return {
      data: result.requests,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/dsar/requests?limit=${limit}&offset=${offset}` }
    };
  }

  @Get('dsar/requests/:id')
  @RequireScopes('dsar:read')
  async getDSAR(@Param('id') id: string) {
    const request = await this.dataGovService.getDSARById(id);
    return { data: request };
  }

  @Post('dsar/requests/:id/verify')
  @RequireScopes('dsar:verify')
  async verifyDSAR(@Param('id') id: string, @Body() body: { verificationMethod: string }) {
    const request = await this.dataGovService.verifyDSARIdentity(id, body.verificationMethod);
    return { data: request };
  }

  @Post('dsar/requests/:id/complete')
  @RequireScopes('dsar:complete')
  async completeDSAR(@Param('id') id: string, @Body() body: { completedBy: string; dataExport?: any }) {
    const request = await this.dataGovService.completeDSAR(id, body.completedBy, body.dataExport);
    return { data: request };
  }

  @Post('dsar/requests/:id/reject')
  @RequireScopes('dsar:reject')
  async rejectDSAR(@Param('id') id: string, @Body() body: { reason: string }) {
    const request = await this.dataGovService.rejectDSAR(id, body.reason);
    return { data: request };
  }
}
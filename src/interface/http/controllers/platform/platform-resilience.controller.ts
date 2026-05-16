import { Controller, Post, Get, Patch, Body, Param, UseGuards, Query, HttpCode } from '@nestjs/common';
import { PlatformResilienceService } from '../../../../application/services/platform/platform-resilience.service';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';

const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1/resilience')
@UseGuards(PlatformApiKeyGuard)
export class PlatformResilienceController {
  constructor(private readonly resilienceService: PlatformResilienceService) {}

  @Get('health')
  @RequireScopes('health:read')
  async getHealth() {
    const health = await this.resilienceService.getHealth();
    return { data: health };
  }

  @Get('health/:component')
  @RequireScopes('health:read')
  async checkComponentHealth(@Param('component') component: string) {
    const result = await this.resilienceService.checkComponentHealth(component);
    return { data: result };
  }

  @Get('incidents')
  @RequireScopes('incident:read')
  async listIncidents(@Query() query: { status?: string; severity?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.resilienceService.listIncidents({
      status: query.status,
      severity: query.severity,
      limit,
      offset
    });
    return {
      data: result.incidents,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/resilience/incidents?limit=${limit}&offset=${offset}` }
    };
  }

  @Get('incidents/:id')
  @RequireScopes('incident:read')
  async getIncident(@Param('id') id: string) {
    const incident = await this.resilienceService.getIncidentById(id);
    return { data: incident };
  }

  @Post('incidents')
  @HttpCode(201)
  @RequireScopes('incident:manage')
  async createIncident(@Body() body: { title: string; description: string; severity: string; components: string[]; createdBy: string }) {
    const incident = await this.resilienceService.createIncident({
      title: body.title,
      description: body.description,
      severity: body.severity as any,
      components: body.components,
      createdBy: body.createdBy
    });
    return { data: incident };
  }

  @Patch('incidents/:id')
  @RequireScopes('incident:manage')
  async resolveIncident(@Param('id') id: string, @Body() body: { status: string; message: string }) {
    const incident = await this.resilienceService.updateIncidentStatus(id, body.status, body.message);
    return { data: incident };
  }

  @Get('circuit-breakers')
  @RequireScopes('health:read')
  async listCBs() {
    const breakers = await this.resilienceService.listCircuitBreakers();
    return { data: breakers };
  }

  @Get('circuit-breakers/:service')
  @RequireScopes('health:read')
  async getCircuitBreaker(@Param('service') service: string) {
    const breaker = await this.resilienceService.getCircuitBreaker(service);
    return { data: breaker };
  }

  @Post('chaos/experiments')
  @HttpCode(201)
  @RequireScopes('chaos:write')
  async runChaos(@Body() body: { name: string; description: string; type: string; targetServices: string[]; parameters: any; createdBy: string }) {
    const experiment = await this.resilienceService.runChaosExperiment({
      name: body.name,
      description: body.description,
      type: body.type,
      targetServices: body.targetServices,
      parameters: body.parameters,
      createdBy: body.createdBy
    });
    return { data: experiment };
  }

  @Get('chaos/experiments')
  @RequireScopes('chaos:read')
  async listChaosExperiments(@Query() query: { status?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.resilienceService.listChaosExperiments({
      status: query.status,
      limit,
      offset
    });
    return {
      data: result.experiments,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/resilience/chaos/experiments?limit=${limit}&offset=${offset}` }
    };
  }

  @Get('chaos/experiments/:id')
  @RequireScopes('chaos:read')
  async getChaosExperiment(@Param('id') id: string) {
    const experiment = await this.resilienceService.getChaosExperimentById(id);
    return { data: experiment };
  }

  @Patch('chaos/experiments/:id')
  @RequireScopes('chaos:write')
  async completeChaosExperiment(@Param('id') id: string, @Body() body: { status: string }) {
    const experiment = await this.resilienceService.completeChaosExperiment(id, body.status as any);
    return { data: experiment };
  }
}
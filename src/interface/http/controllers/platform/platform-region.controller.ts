import { Controller, Post, Get, Patch, Body, Param, UseGuards, Query, HttpCode } from '@nestjs/common';
import { PlatformRegionService } from '../../../../application/services/platform/platform-region.service';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';

const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1/regions')
@UseGuards(PlatformApiKeyGuard)
export class PlatformRegionController {
  constructor(private readonly regionService: PlatformRegionService) {}

  @Get()
  @RequireScopes('region:read')
  async listRegions(@Query() query: { status?: string; isPrimary?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.regionService.listRegions({
      status: query.status,
      isPrimary: query.isPrimary === 'true',
      limit,
      offset
    });
    return {
      data: result.regions,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/regions?limit=${limit}&offset=${offset}` }
    };
  }

  @Get(':id')
  @RequireScopes('region:read')
  async getRegion(@Param('id') id: string) {
    const region = await this.regionService.getRegionById(id);
    return { data: region };
  }

  @Post()
  @HttpCode(201)
  @RequireScopes('region:write')
  async createRegion(@Body() body: { name: string; code: string; location: string; primaryEndpoint: string; isPrimary?: boolean; capacity?: number }) {
    const region = await this.regionService.createRegion(body);
    return { data: region };
  }

  @Patch(':id')
  @RequireScopes('region:write')
  async updateRegion(@Param('id') id: string, @Body() body: { name?: string; location?: string; primaryEndpoint?: string; status?: string; capacity?: number }) {
    const region = await this.regionService.updateRegion(id, body);
    return { data: region };
  }

  @Post(':id/primary')
  @RequireScopes('region:write')
  async setPrimaryRegion(@Param('id') id: string) {
    const region = await this.regionService.setPrimaryRegion(id);
    return { data: region };
  }

  @Post(':id/failover')
  @RequireScopes('region:failover')
  async triggerFailover(@Param('id') id: string, @Body() body: { targetRegionId: string; type: string }, @Query() query: { triggeredBy: string }) {
    const failover = await this.regionService.triggerFailover(id, body.targetRegionId, body.type as any, query.triggeredBy);
    return { data: failover };
  }

  @Get('failovers')
  @RequireScopes('region:read')
  async listFailovers(@Query() query: { regionId?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.regionService.listFailovers(query.regionId, limit, offset);
    return {
      data: result.failovers,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/regions/failovers?limit=${limit}&offset=${offset}` }
    };
  }

  @Get('failovers/:id')
  @RequireScopes('region:read')
  async getFailover(@Param('id') id: string) {
    const failover = await this.regionService.getFailoverById(id);
    return { data: failover };
  }

  @Post('failovers/:id/complete')
  @RequireScopes('region:failover')
  async completeFailover(@Param('id') id: string) {
    const failover = await this.regionService.completeFailover(id);
    return { data: failover };
  }

  @Get('geo-routing')
  @RequireScopes('region:read')
  async getGeoRouting(@Query() query: { activeOnly?: string }) {
    const rules = await this.regionService.listGeoRoutingRules(query.activeOnly === 'true');
    return { data: rules };
  }

  @Post('geo-routing')
  @HttpCode(201)
  @RequireScopes('region:write')
  async createGeoRoutingRule(@Body() body: { countryCodes: string[]; regionCode: string; priority?: number; isActive?: boolean }) {
    const rule = await this.regionService.createGeoRoutingRule({
      countryCodes: body.countryCodes,
      regionCode: body.regionCode,
      priority: body.priority,
      isActive: body.isActive
    });
    return { data: rule };
  }

  @Patch('geo-routing/:id')
  @RequireScopes('region:write')
  async updateGeoRouting(@Param('id') id: string, @Body() body: { regionCode?: string; priority?: number; isActive?: boolean }) {
    const rule = await this.regionService.updateGeoRoutingRule(id, body);
    return { data: rule };
  }

  @Get('geo-routing/:countryCode')
  @RequireScopes('region:read')
  async getGeoRoutingForCountry(@Param('countryCode') countryCode: string) {
    const region = await this.regionService.getGeoRoutingForCountry(countryCode);
    return { data: region };
  }
}
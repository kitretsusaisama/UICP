import { Controller, Post, Get, Patch, Delete, Body, Param, UseGuards, Query, HttpCode } from '@nestjs/common';
import { PlatformConfigService } from '../../../../application/services/platform/platform-config.service';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';

const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1')
@UseGuards(PlatformApiKeyGuard)
export class PlatformConfigController {
  constructor(private readonly configService: PlatformConfigService) {}

  @Get('config')
  @RequireScopes('config:read')
  async getConfig(@Query() query: { key?: string; category?: string }) {
    if (query.key) {
      const config = await this.configService.getByKey(query.key);
      return { data: config };
    }
    if (query.category) {
      const configs = await this.configService.getByCategory(query.category);
      return { data: configs };
    }
    const configs = await this.configService.getPublicConfig();
    return { data: configs };
  }

  @Patch('config')
  @RequireScopes('config:write')
  async updateConfig(@Body() body: { key: string; value: any; category: string; description?: string; isEncrypted?: boolean; isPublic?: boolean }, @Query() query: { updatedBy?: string }) {
    const config = await this.configService.set({
      key: body.key,
      value: body.value,
      category: body.category,
      description: body.description,
      isEncrypted: body.isEncrypted,
      isPublic: body.isPublic,
      updatedBy: query.updatedBy
    });
    return { data: config };
  }

  @Post('config')
  @HttpCode(201)
  @RequireScopes('config:write')
  async createConfig(@Body() body: { key: string; value: any; category: string; description?: string; isEncrypted?: boolean; isPublic?: boolean }, @Query() query: { updatedBy?: string }) {
    const config = await this.configService.set({
      key: body.key,
      value: body.value,
      category: body.category,
      description: body.description,
      isEncrypted: body.isEncrypted,
      isPublic: body.isPublic,
      updatedBy: query.updatedBy
    });
    return { data: config };
  }

  @Delete('config/:key')
  @HttpCode(204)
  @RequireScopes('config:write')
  async deleteConfig(@Param('key') key: string) {
    await this.configService.delete(key);
    return { data: { key, deleted: true } };
  }

  @Get('config/history')
  @RequireScopes('config:read')
  async getConfigHistory(@Query() query: { category?: string; isPublic?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.configService.list({
      category: query.category,
      isPublic: query.isPublic === 'true',
      limit,
      offset
    });
    return {
      data: result.configs,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/config/history?limit=${limit}&offset=${offset}` }
    };
  }

  @Post('config/rollback/:version')
  @RequireScopes('config:write')
  async rollbackConfig(@Param('version') version: string, @Body() body: { key: string }) {
    const config = await this.configService.getByKey(body.key);
    return { data: { rolledBackTo: version, currentVersion: config?.version } };
  }

  @Get('announcements')
  @RequireScopes('announcement:read')
  async listAnnouncements(@Query() query: { type?: string; activeOnly?: string; limit?: string; offset?: string }) {
    const limit = query.limit ? parseInt(query.limit) : 50;
    const offset = query.offset ? parseInt(query.offset) : 0;
    const result = await this.configService.listAnnouncements({
      type: query.type,
      activeOnly: query.activeOnly === 'true',
      limit,
      offset
    });
    return {
      data: result.announcements,
      meta: { total: result.total, page: Math.floor(offset / limit) + 1, per_page: limit, total_pages: Math.ceil(result.total / limit) },
      links: { self: `/platform/v1/announcements?limit=${limit}&offset=${offset}` }
    };
  }

  @Post('announcements')
  @HttpCode(201)
  @RequireScopes('announcement:write')
  async createAnnouncement(@Body() body: { title: string; content: string; type: string; targetTenants?: string[]; startsAt: string; endsAt?: string; createdBy: string }) {
    const announcement = await this.configService.createAnnouncement({
      title: body.title,
      content: body.content,
      type: body.type as any,
      targetTenants: body.targetTenants,
      startsAt: new Date(body.startsAt),
      endsAt: body.endsAt ? new Date(body.endsAt) : undefined,
      createdBy: body.createdBy
    });
    return { data: announcement };
  }

  @Delete('announcements/:id')
  @HttpCode(204)
  @RequireScopes('announcement:delete')
  async deleteAnnouncement(@Param('id') id: string) {
    await this.configService.deleteAnnouncement(id);
    return { data: { id, deleted: true } };
  }

  @Post('config/export')
  @RequireScopes('config:read')
  async exportConfig() {
    const result = await this.configService.exportConfig();
    return { data: result };
  }

  @Post('config/import')
  @HttpCode(201)
  @RequireScopes('config:write')
  async importConfig(@Body() body: { configs: any[]; importedBy: string }) {
    const result = await this.configService.importConfig(body.configs, body.importedBy);
    return { data: result };
  }
}
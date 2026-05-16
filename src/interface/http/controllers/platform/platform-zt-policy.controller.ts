import { Controller, Post, Get, Put, Body, Param, UseGuards, HttpCode } from '@nestjs/common';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';
const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1')
@UseGuards(PlatformApiKeyGuard)
export class PlatformZtPolicyController {
  @Get('zt-policies')
  @RequireScopes('zt-policy:read')
  async list() { return { data: [] }; }

  @Post('zt-policies')
  @HttpCode(201)
  @RequireScopes('zt-policy:write')
  async create(@Body() b: any) { return { data: { id: 'ztp-' + Date.now() } }; }

  @Put('zt-policies/:id/device')
  @RequireScopes('zt-policy:write')
  async updateDevice(@Param('id') id: string, @Body() b: any) { return { data: { id } }; }

  @Put('zt-policies/:id/network')
  @RequireScopes('zt-policy:write')
  async updateNetwork(@Param('id') id: string, @Body() b: any) { return { data: { id } }; }

  @Get('device-posture/:identity')
  @RequireScopes('device-posture:read')
  async getPosture(@Param('identity') id: string) { return { data: { identityId: id, compliant: true } }; }
}
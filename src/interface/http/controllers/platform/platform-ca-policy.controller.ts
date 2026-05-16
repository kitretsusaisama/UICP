import { Controller, Post, Get, Patch, Delete, Body, Param, UseGuards, HttpCode } from '@nestjs/common';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';
const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1/ca-policies')
@UseGuards(PlatformApiKeyGuard)
export class PlatformCaPolicyController {
  @Get()
  @RequireScopes('ca-policy:read')
  async list() { return { data: [] }; }

  @Post()
  @HttpCode(201)
  @RequireScopes('ca-policy:write')
  async create(@Body() b: any) { return { data: { id: 'cap-' + Date.now() } }; }

  @Get(':id')
  @RequireScopes('ca-policy:read')
  async get(@Param('id') id: string) { return { data: { id } }; }

  @Patch(':id')
  @RequireScopes('ca-policy:write')
  async update(@Param('id') id: string, @Body() b: any) { return { data: { id } }; }

  @Delete(':id')
  @HttpCode(204)
  @RequireScopes('ca-policy:delete')
  async delete(@Param('id') id: string) { return { data: { id, deleted: true } }; }

  @Post(':id/test')
  @RequireScopes('ca-policy:read')
  async test(@Param('id') id: string, @Body() b: any) { return { data: { result: 'pass' } }; }
}
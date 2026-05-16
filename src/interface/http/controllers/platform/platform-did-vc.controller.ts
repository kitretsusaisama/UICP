import { Controller, Post, Get, Body, Param, UseGuards, HttpCode } from '@nestjs/common';
import { PlatformApiKeyGuard, PLATFORM_SCOPES_METADATA } from '../../guards/platform-api-key.guard';
import { SetMetadata } from '@nestjs/common';
const RequireScopes = (...s: string[]) => SetMetadata(PLATFORM_SCOPES_METADATA, s);

@Controller('platform/v1/identities')
@UseGuards(PlatformApiKeyGuard)
export class PlatformDidVcController {
  @Post('did/register')
  @HttpCode(201)
  @RequireScopes('did:write')
  async registerDid(@Body() b: any) { return { data: { did: `did:uicp:${Date.now()}`, status: 'registered' } }; }

  @Get('did/:did')
  @RequireScopes('did:read')
  async resolveDid(@Param('did') did: string) { return { data: { did, document: {} } }; }

  @Post('vc/issue')
  @HttpCode(201)
  @RequireScopes('vc:issue')
  async issueVc(@Body() b: any) { return { data: { credentialId: 'vc-' + Date.now(), status: 'issued' } }; }

  @Post('vc/verify')
  @RequireScopes('vc:verify')
  async verifyVc(@Body() b: any) { return { data: { verified: true } }; }

  @Post('vc/revoke')
  @RequireScopes('vc:revoke')
  async revokeVc(@Body() b: any) { return { data: { credentialId: b.credentialId, status: 'revoked' } }; }

  @Get(':id/credentials')
  @RequireScopes('vc:read')
  async listCreds(@Param('id') id: string) { return { data: [] }; }

  @Post(':id/link-did')
  @RequireScopes('did:write')
  async linkDid(@Param('id') id: string, @Body() b: any) { return { data: { did: b.did, linked: true } }; }
}
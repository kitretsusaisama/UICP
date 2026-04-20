import { Governance } from '../../../../src/infrastructure/governance/decorators/governance.decorator';
import { GovernanceGuard } from '../../../../src/infrastructure/governance/guards/governance.guard';
import { Controller, Post, UseGuards, Get, Query, Req, Res, Body, Headers, BadRequestException, Inject, UseGuards } from '@nestjs/common';
import { Request, Response } from 'express';
import { ApiTags, ApiOperation, ApiQuery, ApiResponse } from '@nestjs/swagger';
import { OAuthService } from '../../../../src/application/services/platform/oauth.service';
import { ulid } from 'ulid';
import { CACHE_ADAPTER } from '../../../../src/domain/repositories/cache.repository.interface';
import { CacheAdapter } from '../../../../src/infrastructure/cache/redis-cache.adapter';
import { JwtService } from '@nestjs/jwt';
import { TokenService } from '../../../../src/application/services/token.service';
import { AuditLogWriter } from '../../../../src/application/services/audit-log.writer';
import { ClientBasicAuthGuard } from '../../guards/client-basic-auth.guard';

@ApiTags('OAuth 2.1')
@Controller('v1/oauth2')
export class OAuthController {
  constructor(
    private readonly oauthService: OAuthService,
    private readonly jwtService: JwtService,
    private readonly tokenService: TokenService,
    private readonly auditWriter: AuditLogWriter,
    @Inject(CACHE_ADAPTER) private readonly cache: CacheAdapter
  ) {}

  @Get('authorize')
  @Governance({ owner: 'auth-team', risk: 'critical', auth: 'public' })
  @UseGuards(GovernanceGuard)
  @Governance({ owner: 'platform-team@uicp.com', risk: 'medium', auth: 'client' })
  @ApiOperation({ summary: 'Initiate OIDC Authorization Code Flow (PKCE Required)' })
  @ApiQuery({ name: 'response_type', enum: ['code'], required: true })
  @ApiQuery({ name: 'client_id', required: true })
  @ApiQuery({ name: 'redirect_uri', required: true })
  @ApiQuery({ name: 'code_challenge', required: true })
  @ApiQuery({ name: 'code_challenge_method', enum: ['S256'], required: true })
  @ApiQuery({ name: 'state', required: false })
  @ApiQuery({ name: 'nonce', required: false })
  @ApiResponse({ status: 302, description: 'Redirects to consent/login UI' })
  async authorize(
    @Query('response_type') responseType: string,
    @Query('client_id') clientId: string,
    @Query('redirect_uri') redirectUri: string,
    @Query('code_challenge') codeChallenge: string,
    @Query('code_challenge_method') codeChallengeMethod: string,
    @Query('state') state: string,
    @Query('nonce') nonce: string,
    @Res() res: Response
  ) {
    if (responseType !== 'code') throw new BadRequestException('Only response_type=code is supported');
    if (!clientId) throw new BadRequestException('client_id is required');
    if (!redirectUri) throw new BadRequestException('redirect_uri is required');
    if (codeChallengeMethod !== 'S256') throw new BadRequestException('code_challenge_method must be S256 (PKCE strictly enforced)');

    const appEntity = await this.oauthService.getClientApp(clientId);
    if (!appEntity || !appEntity.redirectUris.includes(redirectUri)) {
        throw new BadRequestException('Invalid redirect_uri');
    }

    const redirectUrl = new URL('https://login.uicp.com/consent');
    redirectUrl.searchParams.set('client_id', clientId);
    redirectUrl.searchParams.set('redirect_uri', redirectUri);
    redirectUrl.searchParams.set('code_challenge', codeChallenge);
    if (state) redirectUrl.searchParams.set('state', state);
    if (nonce) redirectUrl.searchParams.set('nonce', nonce);

    return res.redirect(302, redirectUrl.toString());
  }

  @Post('token')
  @Governance({ owner: 'auth-team', risk: 'critical', auth: 'public' })
  @UseGuards(GovernanceGuard)
  @Governance({ owner: 'platform-team@uicp.com', risk: 'medium', auth: 'client' })
  @ApiOperation({ summary: 'Exchange Authorization Code for Tokens' })
  async token(
    @Body('grant_type') grantType: string,
    @Body('client_id') clientId: string,
    @Body('code') code: string,
    @Body('redirect_uri') redirectUri: string,
    @Body('code_verifier') codeVerifier: string,
    @Req() req: Request
  ) {
    if (grantType !== 'authorization_code') throw new BadRequestException('Only authorization_code grant is supported');
    if (!clientId || !code || !redirectUri || !codeVerifier) {
      throw new BadRequestException('Missing required parameters (client_id, code, redirect_uri, code_verifier)');
    }

    const { tokens, user, tenantId } = await this.oauthService.exchangeToken({
      clientId,
      code,
      redirectUri,
      codeVerifier
    });

    return {
      access_token: tokens.accessToken,
      id_token: tokens.idToken,
      refresh_token: tokens.refreshToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'openid profile email'
    };
  }

  @Post('introspect')
  @Governance({ owner: 'auth-team', risk: 'high', auth: 'client' })
  @UseGuards(ClientBasicAuthGuard)
  @UseGuards(GovernanceGuard)
  @Governance({ owner: 'platform-team@uicp.com', risk: 'medium', auth: 'client' })
  @ApiOperation({ summary: 'Introspect a token (OAuth 2.0 / RFC 7662)' })
  async introspect(@Req() req: any, @Body() body: any) {
    const { token } = body;
    if (!token) {
       return { active: false }; // Silent failure to prevent leak
    }

    try {
       // Decode without verifying signature first to extract JTI and type
       const decoded = this.jwtService.decode(token) as any;
       if (!decoded) return { active: false };

       // Check Redis revocation blocklist
       const jti = decoded.jti;
       if (jti) {
          const isRevoked = await this.cache.get(`jti:${jti}`);
          if (isRevoked) return { active: false };
       }

       // Verify JWT signature securely
       const verified = this.jwtService.verify(token);

       // Must belong to the same tenant as the client performing introspection
       const clientApp = req.clientApp;
       if (verified.tenantId !== clientApp.tenantId) {
          return { active: false };
       }

       return {
         active: true,
         sub: verified.sub,
         client_id: clientApp.clientId,
         scope: verified.scope || '',
         exp: verified.exp,
         iat: verified.iat,
         iss: verified.iss || 'https://auth.uicp.com',
         jti: verified.jti,
         tenant_id: verified.tenantId
       };
    } catch (err) {
       // Signature mismatch, expired, or malformed
       return { active: false };
    }
  }

  @Post('revoke')
  @Governance({ owner: 'auth-team', risk: 'high', auth: 'client' })
  @UseGuards(ClientBasicAuthGuard)
  @UseGuards(GovernanceGuard)
  @Governance({ owner: 'platform-team@uicp.com', risk: 'medium', auth: 'client' })
  @ApiOperation({ summary: 'Revoke a token (OAuth 2.0 / RFC 7009)' })
  async revoke(@Req() req: any, @Body() body: any) {
    const { token, token_type_hint } = body;
    if (!token) {
       return { success: true, data: { revoked: true } }; // Idempotent per RFC
    }

    try {
       // Decode token to extract JTI
       const decoded = this.jwtService.decode(token) as any;
       if (decoded && decoded.jti) {
          const exp = decoded.exp || Math.floor(Date.now() / 1000) + 3600;
          const ttl = Math.max(0, exp - Math.floor(Date.now() / 1000));
          if (ttl > 0) {
             // Blocklist access token
             await this.cache.set(`jti:${decoded.jti}`, '1', ttl);
          }

          // If token type is refresh, also purge family in database
          if (token_type_hint === 'refresh_token' || decoded.type === 'refresh') {
             await this.tokenService.revokeFamily(decoded.jti, req.clientApp.tenantId, 'Revoked via /revoke endpoint');
          }

          this.auditWriter.writeLog({
             auditId: ulid(),
             tenantId: req.clientApp.tenantId,
             actorId: req.clientApp.clientId,
             event: 'TOKEN_REVOKED',
             timestamp: Date.now(),
             metadata: JSON.stringify({ jti: decoded.jti, type: token_type_hint })
          });
       }
    } catch (err) {
       // Continue silently; revocation API must always return success per RFC
    }

    return {
      success: true,
      data: { revoked: true },
      meta: { requestId: req.headers['x-request-id'] || ulid(), timestamp: Math.floor(Date.now()/1000) }
    };
  }
}

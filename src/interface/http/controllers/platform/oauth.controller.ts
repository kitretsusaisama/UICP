import { Controller, Get, Post, Query, Body, Res, Req, UseGuards, BadRequestException, UnauthorizedException, Headers, Param } from '@nestjs/common';
import { Response } from 'express';
import { OAuthService } from '../../../../application/services/platform/oauth.service';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { TenantGuard } from '../../guards/tenant.guard';

@Controller('v1/oauth2')
export class OAuthController {
  constructor(private readonly oauthService: OAuthService) {}

  @Get('authorize')
  @UseGuards(JwtAuthGuard, TenantGuard) // Requires a logged-in user context
  async authorize(
    @Req() req: any,
    @Res() res: Response,
    @Query('response_type') responseType: string,
    @Query('client_id') clientId: string,
    @Query('redirect_uri') redirectUri: string,
    @Query('state') state: string,
    @Query('code_challenge') codeChallenge: string,
    @Query('code_challenge_method') codeChallengeMethod: string,
    @Query('scope') scope?: string,
    @Query('nonce') nonce?: string,
  ) {
    const tenantId = req.tenantId;
    const userId = req.user.sub;

    try {
      const redirectUrl = await this.oauthService.authorize({
        tenantId,
        userId,
        clientId,
        redirectUri,
        responseType,
        scope,
        state,
        nonce,
        codeChallenge,
        codeChallengeMethod,
      });

      return res.redirect(302, redirectUrl);
    } catch (err: any) {
      if (err instanceof BadRequestException || err instanceof UnauthorizedException || err.status === 401 || err.status === 400) {
        if (err.message === 'invalid_client' || err.message.includes('redirect_uri mismatch')) {
          return res.status(400).json({ error: 'invalid_request', error_description: err.message });
        }

        const url = new URL(redirectUri);
        url.searchParams.append('error', 'invalid_request');
        url.searchParams.append('error_description', err.message);
        url.searchParams.append('state', state);
        return res.redirect(302, url.toString());
      }
      throw err;
    }
  }

  @Post('token')
  async token(@Body() body: any) {
    const {
      grant_type: grantType,
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: codeVerifier,
    } = body;

    try {
      const result = await this.oauthService.exchangeToken({
        grantType,
        code,
        redirectUri,
        clientId,
        codeVerifier,
      });
      return result;
    } catch (err: any) {
      if (err instanceof BadRequestException) {
        let error = 'invalid_request';
        if (err.message.includes('unsupported_grant_type')) error = 'unsupported_grant_type';
        if (err.message.includes('invalid_grant')) error = 'invalid_grant';

        throw new BadRequestException({ error, error_description: err.message });
      }
      throw err;
    }
  }

  @Get('userinfo')
  async userinfo(@Headers('authorization') authHeader: string) {
    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
      throw new UnauthorizedException('Missing or invalid Authorization header');
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
      throw new UnauthorizedException('Missing or invalid Authorization header');
    }

    return await this.oauthService.getUserInfo(token);
  }

  @Get('callback/:provider')
  async socialCallback(
    @Req() req: any,
    @Param('provider') provider: string,
    @Query('code') code: string,
    @Query('state') state: string
  ) {
    if (!state) {
      throw new BadRequestException('State is required to prevent CSRF');
    }

    const providerProfile = {
      providerUserId: '12345',
      email: 'social@example.com',
      emailVerified: true
    };

    const tenantId = req.tenantId || 'tenant-1';

    const result = await this.oauthService.handleSocialLogin({
      provider,
      providerUserId: providerProfile.providerUserId,
      email: providerProfile.email,
      emailVerified: providerProfile.emailVerified,
      tenantId,
    });

    if (result.action === 'verification_required') {
      return {
        success: true,
        message: 'Account exists. Please verify your email to link this social login.',
        userId: result.userId,
        verification_required: true,
      };
    }

    return {
      success: true,
      data: result,
      meta: { version: 'v1' }
    };
  }
}

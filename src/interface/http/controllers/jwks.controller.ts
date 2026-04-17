import { Controller, Get, Header, HttpCode, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiTags } from '@nestjs/swagger';

import { GetJwksHandler } from '../../../application/queries/get-jwks/get-jwks.handler';

/**
 * JWKS + OIDC Discovery endpoints.
 *
 * Routes:
 *   GET /.well-known/jwks.json              — JSON Web Key Set (RFC 7517)
 *   GET /.well-known/openid-configuration   — OIDC discovery document
 *
 * Implements: Req 7.6 (JWKS endpoint with Cache-Control: public, max-age=3600)
 */
@ApiTags('Discovery')
@Controller('.well-known')
export class JwksController {
  constructor(
    private readonly getJwksHandler: GetJwksHandler,
    private readonly config: ConfigService,
  ) {}

  // ── GET /.well-known/jwks.json ─────────────────────────────────────────────

  @Get('jwks.json')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'public, max-age=3600')
  getJwks() {
    return this.getJwksHandler.handle();
  }

  // ── GET /.well-known/openid-configuration ──────────────────────────────────

  @Get('openid-configuration')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'public, max-age=3600')
  getOidcConfiguration() {
    const issuer = this.config.get<string>('OIDC_ISSUER', 'https://uicp.example.com');
    const baseUrl = issuer.replace(/\/$/, '');

    return {
      issuer,
      authorization_endpoint: `${baseUrl}/v1/auth/oauth/authorize`,
      token_endpoint: `${baseUrl}/v1/auth/refresh`,
      userinfo_endpoint: `${baseUrl}/v1/core/me`,
      jwks_uri: `${baseUrl}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'profile', 'email'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'tid', 'mid', 'aid', 'sid', 'pv', 'mv', 'capabilities', 'acr', 'amr'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
    };
  }
}

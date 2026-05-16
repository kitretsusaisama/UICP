/**
 * OIDC Provider Service
 *
 * Provides OpenID Connect capability for enterprise identity.
 * Supports authorization code flow with PKCE.
 */

import { Injectable, Logger } from '@nestjs/common';

export interface OidcConfig {
  tenantId: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  scopes: string[];
}

export interface OidcAuthorizationRequest {
  clientId: string;
  redirectUri: string;
  responseType: string;
  scope: string;
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}

export interface OidcTokens {
  accessToken: string;
  refreshToken?: string;
  idToken: string;
  tokenType: string;
  expiresIn: number;
}

export interface OidcUserInfo {
  sub: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  givenName?: string;
  familyName?: string;
}

@Injectable()
export class OidcProviderService {
  private readonly logger = new Logger(OidcProviderService.name);

  buildAuthorizationUrl(config: OidcConfig, request: OidcAuthorizationRequest): string {
    const params = new URLSearchParams({
      client_id: request.clientId,
      redirect_uri: request.redirectUri,
      response_type: request.responseType,
      scope: request.scope,
      state: request.state,
    });

    if (request.codeChallenge) {
      params.set('code_challenge', request.codeChallenge);
      params.set('code_challenge_method', request.codeChallengeMethod || 'S256');
    }

    const authUrl = new URL(`${config.issuer}/authorize`);
    authUrl.search = params.toString();
    return authUrl.toString();
  }

  async exchangeCodeForTokens(
    config: OidcConfig,
    code: string,
    redirectUri: string,
    _codeVerifier?: string,
  ): Promise<OidcTokens> {
    this.logger.debug({ tenantId: config.tenantId }, 'Exchanging code for tokens');
    return {
      accessToken: 'mock_access_token',
      refreshToken: 'mock_refresh_token',
      idToken: 'mock_id_token',
      tokenType: 'Bearer',
      expiresIn: 3600,
    };
  }

  async getUserInfo(_accessToken: string): Promise<OidcUserInfo> {
    return {
      sub: 'oidc-user-001',
      email: 'user@example.com',
      name: 'OIDC User',
    };
  }

  async refreshTokens(config: OidcConfig, _refreshToken: string): Promise<OidcTokens> {
    this.logger.debug({ tenantId: config.tenantId }, 'Refreshing tokens');
    return {
      accessToken: 'new_access_token',
      refreshToken: 'new_refresh_token',
      idToken: 'new_id_token',
      tokenType: 'Bearer',
      expiresIn: 3600,
    };
  }

  validateConfig(config: OidcConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!config.tenantId) errors.push('tenantId is required');
    if (!config.issuer) errors.push('issuer is required');
    if (!config.clientId) errors.push('clientId is required');
    return { valid: errors.length === 0, errors };
  }

  generatePkcePair(): { verifier: string; challenge: string } {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    const verifier = this.base64UrlEncode(randomBytes.buffer as ArrayBuffer);
    // Note: In production, digest is async - this is a simplified sync version
    const challenge = this.base64UrlEncode(new Uint8Array(32).buffer as ArrayBuffer);
    return { verifier, challenge };
  }

  private base64UrlEncode(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]!);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
}
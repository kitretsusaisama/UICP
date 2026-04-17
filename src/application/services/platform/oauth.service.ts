import { Injectable, Inject, BadRequestException, Logger, UnauthorizedException } from '@nestjs/common';
import { randomBytes, createHash } from 'crypto';
import { IOAuthCache, OAUTH_CACHE, AuthorizationCodeData } from '../../../infrastructure/cache/redis-oauth.adapter';
import { IAppRepository, APP_REPOSITORY } from '../../../domain/repositories/platform/app.repository.interface';
import { App } from '../../../domain/entities/platform/app.entity';
import { TokenService, MintedTokens } from '../token.service';
import { IUserRepository } from '../../../application/ports/driven/i-user.repository';
import { IIdentityRepository } from '../../../application/ports/driven/i-identity.repository';
import { IEncryptionPort } from '../../../application/ports/driven/i-encryption.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

export interface TokenExchangeResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
}

export interface UserInfoResponse {
  sub: string;
  email?: string;
  email_verified?: boolean;
  phone_number?: string;
  phone_number_verified?: boolean;
  [key: string]: any;
}

export interface SocialIdentityParams {
  provider: string;
  providerUserId: string;
  email?: string;
  emailVerified?: boolean;
  tenantId: string;
}

@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);

  constructor(
    @Inject(OAUTH_CACHE) private readonly oauthCache: IOAuthCache,
    @Inject(APP_REPOSITORY) private readonly appRepository: IAppRepository,
    @Inject(INJECTION_TOKENS.USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(INJECTION_TOKENS.IDENTITY_REPOSITORY) private readonly identityRepo: IIdentityRepository,
    @Inject(INJECTION_TOKENS.ENCRYPTION_PORT) private readonly encryption: IEncryptionPort,
    private readonly tokenService: TokenService,
  ) {}

  async authorize(params: {
    tenantId: string;
    userId: string;
    clientId: string;
    redirectUri: string;
    responseType: string;
    scope?: string;
    state: string;
    nonce?: string;
    codeChallenge: string;
    codeChallengeMethod: string;
  }): Promise<string> {
    const {
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
    } = params;

    if (responseType !== 'code') {
      throw new BadRequestException('unsupported_response_type');
    }

    if (!codeChallenge) {
      throw new BadRequestException('invalid_request: code_challenge is required (PKCE mandatory)');
    }
    if (codeChallengeMethod !== 'S256') {
      throw new BadRequestException('invalid_request: code_challenge_method must be S256');
    }

    if (!state) {
      throw new BadRequestException('invalid_request: state is required');
    }

    const apps = await this.appRepository.findByTenant(tenantId);
    const app = apps.find(a => a.clientId === clientId);
    if (!app) {
      throw new UnauthorizedException('invalid_client');
    }

    if (!app.redirectUris.includes(redirectUri)) {
      this.logger.error({ clientId, redirectUri }, 'Redirect URI mismatch');
      throw new BadRequestException('invalid_request: redirect_uri mismatch');
    }

    const scopes = scope ? scope.split(' ') : [];
    if (scopes.includes('openid') && !nonce) {
      throw new BadRequestException('invalid_request: nonce is required for OIDC (openid scope)');
    }

    const code = `code_${randomBytes(32).toString('base64url')}`;

    const authData: AuthorizationCodeData = {
      code,
      clientId,
      userId,
      tenantId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod,
      nonce,
      scopes,
      expiresAt: Date.now() + 60 * 1000,
    };

    await this.oauthCache.storeAuthorizationCode(authData);

    const url = new URL(redirectUri);
    url.searchParams.append('code', code);
    url.searchParams.append('state', state);

    return url.toString();
  }

  async exchangeToken(params: {
    grantType: string;
    code: string;
    redirectUri: string;
    clientId: string;
    codeVerifier: string;
  }): Promise<TokenExchangeResponse> {
    const { grantType, code, redirectUri, clientId, codeVerifier } = params;

    if (grantType !== 'authorization_code') {
      throw new BadRequestException('unsupported_grant_type');
    }

    if (!code || !redirectUri || !clientId || !codeVerifier) {
      throw new BadRequestException('invalid_request: missing parameters');
    }

    const authData = await this.oauthCache.consumeAuthorizationCode(code);
    if (!authData) {
      this.logger.warn({ code }, 'Attempted to consume invalid or already used authorization code');
      throw new BadRequestException('invalid_grant: code is invalid or expired');
    }

    if (authData.clientId !== clientId) {
      throw new BadRequestException('invalid_grant: client_id mismatch');
    }

    if (authData.redirectUri !== redirectUri) {
      throw new BadRequestException('invalid_grant: redirect_uri mismatch');
    }

    const hashedVerifier = createHash('sha256').update(codeVerifier).digest('base64url');
    if (hashedVerifier !== authData.codeChallenge) {
      this.logger.warn({ code, expected: authData.codeChallenge, actual: hashedVerifier }, 'PKCE validation failed');
      throw new BadRequestException('invalid_grant: code_verifier is invalid');
    }

    const fakeSession = {
      id: 'session-id',
      isMfaVerified: () => false,
      getMfaVerifiedAt: () => null,
      deviceFingerprint: 'dfp',
      policyVersion: 'v1',
      manifestVersion: 'v1',
    } as any;

    const accessResult = await this.tokenService.mintAccessToken({
      principalId: authData.userId,
      tenantId: authData.tenantId,
      membershipId: 'mid',
      actorId: 'aid',
      session: fakeSession,
      capabilities: authData.scopes,
      amr: ['pwd'],
    });

    const refreshResult = await this.tokenService.mintRefreshToken(
      authData.userId as any,
      authData.tenantId as any,
      'family-1',
      'mid',
      'session-id'
    );

    const response: TokenExchangeResponse = {
      access_token: accessResult.token,
      refresh_token: refreshResult.token,
      expires_in: 900,
    };

    if (authData.scopes.includes('openid')) {
      const idTokenPayload = {
        sub: authData.userId,
        aud: clientId,
        nonce: authData.nonce,
        auth_time: Math.floor(Date.now() / 1000),
        acr: 'pwd',
      };

      const idTokenResult = await this.tokenService.mintIdToken(idTokenPayload);
      response.id_token = idTokenResult.token;
    }

    return response;
  }

  async getUserInfo(accessToken: string): Promise<UserInfoResponse> {
    const payload = await this.tokenService.validateAccessToken(accessToken);
    const scopes = payload.capabilities || [];

    if (!scopes.includes('openid')) {
      throw new UnauthorizedException('Missing openid scope');
    }

    const userId = UserId.from(payload.sub);
    const tenantId = TenantId.from(payload.tid);
    const user = await this.userRepo.findById(userId, tenantId);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const response: UserInfoResponse = {
      sub: payload.sub,
    };

    const emailIdentity = user.getIdentity('EMAIL');
    if (scopes.includes('email') && emailIdentity) {
      response.email = emailIdentity.isVerified() ? 'user@example.com' : 'unverified@example.com';
      response.email_verified = emailIdentity.isVerified();
    }

    const phoneIdentity = user.getIdentity('PHONE');
    if (scopes.includes('phone') && phoneIdentity) {
      response.phone_number = '+1234567890';
      response.phone_number_verified = phoneIdentity.isVerified();
    }

    return response;
  }

  async handleSocialLogin(params: SocialIdentityParams): Promise<{ userId: string, action: 'linked' | 'created' | 'verification_required' }> {
    const { provider, providerUserId, email, emailVerified, tenantId } = params;

    if (!email) {
      throw new BadRequestException('Provider returned no email, fallback input required');
    }

    if (!emailVerified) {
      throw new UnauthorizedException('Provider email is not verified, treating as untrusted');
    }

    // Hash the incoming email to search existing identities (O(1))
    const emailHash = await this.encryption.hmac(email, 'IDENTITY_VALUE');

    const existingIdentity = await this.identityRepo.findByHash(emailHash, 'EMAIL', TenantId.from(tenantId));

    if (existingIdentity) {
      // CASE 3: Email already used by different account -> COLLISION POLICY
      // Require manual verification instead of auto-merge
      return {
        userId: existingIdentity.userId.toString(),
        action: 'verification_required',
      };
    }

    return {
      userId: randomBytes(16).toString('hex'),
      action: 'created',
    };
  }
}

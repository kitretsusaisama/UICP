import { QueueBackpressureGuard } from '../../guards/queue-backpressure.guard';
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Inject,
  Logger,
  Param,
  Post,
  Query,
  Redirect,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiHeader, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';
import { createHash, randomUUID } from 'crypto';

import { OAuthCallbackCommand, OAuthProvider } from '@application/commands/oauth-callback/oauth-callback.command';
import { OAuthCallbackHandler } from '@application/commands/oauth-callback/oauth-callback.handler';
import { INJECTION_TOKENS } from '@application/ports/injection-tokens';
import { ICachePort } from '@application/ports/driven/i-cache.port';
import { TokenService } from '@application/services/token.service';
import { RuntimeIdentityService } from '@application/services/runtime-identity.service';
import { SessionService } from '@application/services/session.service';
import { SessionId } from '@domain/value-objects/session-id.vo';
import { TenantId } from '@domain/value-objects/tenant-id.vo';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { parseTenantId } from '../../tenant/tenant-context';

// Helpers
interface AuthRequest {
  headers: Record<string, string | string[] | undefined>;
  get?: (name: string) => string | undefined;
  protocol?: string;
  ip?: string;
}

function hashIp(ip: string): string {
  return createHash('sha256').update(ip).digest('hex').slice(0, 16);
}

function getClientIp(req: AuthRequest): string {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = Array.isArray(forwarded) ? forwarded[0] : (forwarded?.split(',')[0] ?? req.ip ?? '0.0.0.0');
  return (ip ?? '0.0.0.0').trim();
}

/**
 * Auth OAuth Controller
 * Handles: oauth/:provider (initiate), oauth/:provider/callback
 */
@ApiTags('Auth - OAuth')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/auth/oauth')
@UseGuards(QueueBackpressureGuard)
export class AuthOAuthController {
  private readonly logger = new Logger(AuthOAuthController.name);

  constructor(
    private readonly oauthCallbackHandler: OAuthCallbackHandler,
    private readonly tokenService: TokenService,
    private readonly runtimeIdentityService: RuntimeIdentityService,
    private readonly sessionService: SessionService,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {}

  private validateProvider(provider: string): void {
    const valid: OAuthProvider[] = ['google', 'github', 'apple', 'microsoft'];
    if (!valid.includes(provider as OAuthProvider)) {
      throw new BadRequestException({
        error: { code: 'UNSUPPORTED_PROVIDER', message: `Unsupported OAuth provider: ${provider}` },
      });
    }
  }

  private buildOAuthUrl(provider: OAuthProvider, state: string, redirectUri: string): string {
    const urls: Record<OAuthProvider, string> = {
      google: `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`,
      github: `https://github.com/login/oauth/authorize?response_type=code&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`,
      apple: `https://appleid.apple.com/auth/authorize?response_type=code&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`,
      microsoft: `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`,
    };
    return urls[provider] ?? '';
  }

  private async buildAuthResponse(accessToken: string, refreshToken?: string) {
    const claims = this.tokenService.parseAccessToken(accessToken);
    const runtimeContext = await this.runtimeIdentityService.getContext(claims.sub, claims.tid, claims.aid);
    const session = await this.sessionService.findById(SessionId.from(claims.sid), TenantId.from(claims.tid));

    return {
      principal: runtimeContext
        ? {
            id: runtimeContext.principalId,
            status: runtimeContext.principalStatus,
            authMethodsSummary: runtimeContext.authMethodsSummary,
          }
        : { id: claims.sub, status: 'active', authMethodsSummary: [] },
      membership: runtimeContext
        ? {
            id: runtimeContext.membershipId,
            tenantId: runtimeContext.tenantId,
            status: runtimeContext.membershipStatus,
            tenantType: runtimeContext.tenantType,
            isolationTier: runtimeContext.isolationTier,
          }
        : undefined,
      actor: runtimeContext
        ? {
            id: runtimeContext.actorId,
            type: runtimeContext.actorType,
            displayName: runtimeContext.actorDisplayName,
            isDefault: true,
          }
        : undefined,
      session: session
        ? {
            id: session.id.toString(),
            recentAuthAt: session.getRecentAuthAt()?.toISOString(),
            expiresAt: session.getExpiresAt().toISOString(),
            deviceSummary: {
              browser: session.uaBrowser,
              os: session.uaOs,
              deviceType: session.uaDeviceType,
            },
          }
        : { id: claims.sid },
      accessToken,
      refreshToken,
      policyVersion: claims.pv,
      manifestVersion: claims.mv,
    };
  }

  // GET /auth/oauth/:provider
  @Get(':provider')
  @Redirect()
  async oauthInitiate(
    @Param('provider') provider: string,
    @Headers('x-tenant-id') rawTenantId: string,
    @Req() req: AuthRequest,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    this.validateProvider(provider);

    // Generate CSRF state and store in Redis with 5-min TTL
    const state = randomUUID();
    await this.cache.set(`oauth-state:${tenantId}:${state}`, '1', 300);

    // Build provider authorization URL
    const host = req.get?.('host') ?? 'localhost:3000';
    const protocol = req.protocol ?? 'https';
    const redirectUri = `${protocol}://${host}/v1/auth/oauth/${provider}/callback`;
    const authUrl = this.buildOAuthUrl(provider as OAuthProvider, state, redirectUri);

    this.logger.log({ provider, tenantId }, 'OAuth initiation');
    return { url: authUrl, statusCode: HttpStatus.FOUND };
  }

  // GET /auth/oauth/:provider/callback
  @Get(':provider/callback')
  @HttpCode(HttpStatus.OK)
  async oauthCallback(
    @Param('provider') provider: string,
    @Headers('x-tenant-id') rawTenantId: string,
    @Query('code') code: string,
    @Query('state') state: string,
    @Req() req: AuthRequest,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    this.validateProvider(provider);

    if (!code || !state) {
      throw new BadRequestException({
        error: { code: 'MISSING_OAUTH_PARAMS', message: 'code and state are required' },
      });
    }

    // Verify CSRF state
    const storedState = await this.cache.get(`oauth-state:${tenantId}:${state}`);
    if (!storedState) {
      throw new BadRequestException({
        error: { code: 'INVALID_OAUTH_STATE', message: 'Invalid or expired OAuth state' },
      });
    }
    await this.cache.del(`oauth-state:${tenantId}:${state}`);

    const host = req.get?.('host') ?? 'localhost:3000';
    const protocol = req.protocol ?? 'https';
    const redirectUri = `${protocol}://${host}/v1/auth/oauth/${provider}/callback`;
    const ipHash = hashIp(getClientIp(req));
    const userAgent = (req.headers['user-agent'] as string | undefined) ?? '';

    const result = await this.oauthCallbackHandler.handle(
      new OAuthCallbackCommand(
        tenantId,
        provider as OAuthProvider,
        code,
        state,
        state,
        redirectUri,
        ipHash,
        userAgent,
        '',
      ),
    );
    return { data: await this.buildAuthResponse(result.accessToken, result.refreshToken) };
  }
}

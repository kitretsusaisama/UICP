import { QueueBackpressureGuard } from '../../guards/queue-backpressure.guard';
import {
  BadRequestException,
  Body,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Inject,
  Logger,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { Response } from 'express';
import { ApiHeader, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';
import { createHash } from 'crypto';

import { SignupEmailCommand } from '@application/commands/signup-email/signup-email.command';
import { SignupEmailHandler } from '@application/commands/signup-email/signup-email.handler';
import { SignupPhoneCommand } from '@application/commands/signup-phone/signup-phone.command';
import { SignupPhoneHandler } from '@application/commands/signup-phone/signup-phone.handler';
import { LoginCommand } from '@application/commands/login/login.command';
import { LoginHandler } from '@application/commands/login/login.handler';
import { RefreshTokenCommand } from '@application/commands/refresh-token/refresh-token.command';
import { RefreshTokenHandler } from '@application/commands/refresh-token/refresh-token.handler';
import { LogoutCommand } from '@application/commands/logout/logout.command';
import { LogoutHandler } from '@application/commands/logout/logout.handler';
import { LogoutAllCommand } from '@application/commands/logout-all/logout-all.command';
import { LogoutAllHandler } from '@application/commands/logout-all/logout-all.handler';
import { RuntimeIdentityService } from '@application/services/runtime-identity.service';
import { SessionService } from '@application/services/session.service';
import { TokenService } from '@application/services/token.service';
import { INJECTION_TOKENS } from '@application/ports/injection-tokens';
import { ICachePort } from '@application/ports/driven/i-cache.port';
import { SessionId } from '@domain/value-objects/session-id.vo';
import { TenantId } from '@domain/value-objects/tenant-id.vo';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { ClientBasicAuthGuard } from '../../guards/client-basic-auth.guard';
import { IdempotencyInterceptor } from '../../interceptors/idempotency.interceptor';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { signupDto, loginDto, refreshDto, introspectDto, switchActorDto } from '../../dtos';
import { parseTenantId } from '../../tenant/tenant-context';

// Helpers
interface AuthRequest {
  headers: Record<string, string | string[] | undefined>;
  principalId: string;
  userId: string;
  membershipId?: string;
  actorId?: string;
  sessionId: string;
  capabilities?: string[];
  ip?: string;
  protocol?: string;
  get?: (name: string) => string | undefined;
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
 * Core Authentication Controller
 * Handles: signup, login, refresh, logout, logout-all, actor/switch, introspect
 */
@ApiTags('Auth - Core')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/auth')
@UseGuards(QueueBackpressureGuard)
export class AuthCoreController {
  private readonly logger = new Logger(AuthCoreController.name);

  constructor(
    private readonly signupHandler: SignupEmailHandler,
    private readonly signupPhoneHandler: SignupPhoneHandler,
    private readonly loginHandler: LoginHandler,
    private readonly refreshHandler: RefreshTokenHandler,
    private readonly logoutHandler: LogoutHandler,
    private readonly logoutAllHandler: LogoutAllHandler,
    private readonly runtimeIdentityService: RuntimeIdentityService,
    private readonly tokenService: TokenService,
    private readonly sessionService: SessionService,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {}

  // POST /auth/signup
  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  @UseInterceptors(IdempotencyInterceptor)
  async signup(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(signupDto)) body: z.infer<typeof signupDto>,
    @Res() res: Response,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const identityType = body.identityType ?? (body.phone ? 'PHONE' : 'EMAIL');
    const result =
      identityType === 'PHONE'
        ? await this.signupPhoneHandler.handle(
            new SignupPhoneCommand(tenantId, body.phone ?? '', body.password),
          )
        : await this.signupHandler.handle(
            new SignupEmailCommand(tenantId, body.email ?? '', body.password),
          );
    const principalId = result.userId;
    res.setHeader('Location', `/v1/users/${principalId}`);
    return {
      data: {
        pending: true,
        principalId,
        challenge: {
          purpose: 'IDENTITY_VERIFICATION',
          channel: identityType,
        },
        message: result.message,
      },
    };
  }

  // POST /auth/login
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(loginDto)) body: z.infer<typeof loginDto>,
    @Req() req: AuthRequest,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const ipHash = hashIp(getClientIp(req));
    const userAgent = (req.headers['user-agent'] as string | undefined) ?? '';

    const result = await this.loginHandler.handle(
      new LoginCommand(
        tenantId,
        body.identity,
        body.password,
        ipHash,
        userAgent,
        body.deviceFingerprint,
        body.identityType,
      ),
    );
    return { data: await this.buildAuthResponse(result.accessToken, result.refreshToken) };
  }

  // POST /auth/refresh
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(refreshDto)) body: z.infer<typeof refreshDto>,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const result = await this.refreshHandler.handle(
      new RefreshTokenCommand(tenantId, body.refreshToken),
    );
    return { data: await this.buildAuthResponse(result.accessToken, result.refreshToken) };
  }

  // POST /auth/logout
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async logout(@Req() req: AuthRequest & { jti?: string; jwtTid?: string }) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const expiresAt = new Date(Date.now() + 900_000);
    const principalId = req.principalId ?? req.userId;
    const result = await this.logoutHandler.handle(
      new LogoutCommand(tenantId, principalId, req.sessionId, req['jti'] ?? '', expiresAt),
    );
    return { data: result };
  }

  // POST /auth/logout-all
  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async logoutAll(@Req() req: AuthRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const principalId = req.principalId ?? req.userId;
    const result = await this.logoutAllHandler.handle(
      new LogoutAllCommand(tenantId, principalId),
    );
    return { data: result };
  }

  // POST /auth/actor/switch
  @Post('actor/switch')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async switchActor(
    @Req() req: AuthRequest,
    @Body(new ZodValidationPipe(switchActorDto)) body: z.infer<typeof switchActorDto>,
  ) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    if (!req.principalId || !req.membershipId) {
      throw new BadRequestException({
        error: { code: 'MISSING_RUNTIME_CONTEXT', message: 'Principal and membership context are required for actor switching' },
      });
    }

    const runtimeContext = await this.runtimeIdentityService.getContext(req.principalId, tenantId, body.actorId);
    if (!runtimeContext || runtimeContext.membershipId !== req.membershipId) {
      throw new BadRequestException({
        error: { code: 'ACTOR_NOT_AVAILABLE', message: `Actor ${body.actorId} is not available for the current membership` },
      });
    }

    const session = await this.sessionService.findById(SessionId.from(req.sessionId), TenantId.from(tenantId));
    if (!session) {
      throw new BadRequestException({
        error: { code: 'SESSION_NOT_FOUND', message: 'Session not found for actor switch' },
      });
    }

    const access = await this.tokenService.mintAccessToken({
      principalId: runtimeContext.principalId,
      tenantId,
      membershipId: runtimeContext.membershipId,
      actorId: runtimeContext.actorId,
      session,
      capabilities: req.capabilities ?? [],
      roles: ['member'],
      perms: req.capabilities ?? [],
      amr: ['pwd'],
      policyVersion: session.policyVersion ?? 'legacy-policy-v1',
      manifestVersion: session.manifestVersion ?? 'legacy-manifest-v1',
    });

    return {
      data: {
        accessToken: access.token,
        actor: {
          id: runtimeContext.actorId,
          type: runtimeContext.actorType,
          displayName: runtimeContext.actorDisplayName,
          isDefault: false,
        },
        effectiveCapabilitiesVersion: session.policyVersion ?? 'legacy-policy-v1',
      },
    };
  }

  // POST /auth/oauth2/introspect
  @Post('oauth2/introspect')
  @HttpCode(HttpStatus.OK)
  @UseGuards(ClientBasicAuthGuard)
  async introspectToken(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(introspectDto)) body: z.infer<typeof introspectDto>,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    try {
      const payload = await this.tokenService.validateAccessToken(body.token);
      if (payload.tid !== tenantId) {
        return { data: { active: false } };
      }

      const scopes = payload.capabilities ?? payload.perms ?? [];

      return {
        data: {
          active: true,
          sub: payload.sub,
          aud: payload.aud,
          iss: payload.iss,
          exp: payload.exp,
          iat: payload.iat,
          scope: scopes.join(' '),
          roles: payload.roles ?? [],
          client_id: 'uicp',
          jti: payload.jti,
          acr: payload.acr,
          amr: payload.amr
        }
      };
    } catch (err) {
      return { data: { active: false } };
    }
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
}

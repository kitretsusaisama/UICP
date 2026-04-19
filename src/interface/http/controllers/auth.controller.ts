import { QueueBackpressureGuard } from '../guards/queue-backpressure.guard';
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
  UseInterceptors,
} from '@nestjs/common';
import { ApiHeader, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';
import { createHash } from 'crypto';

import { SignupEmailCommand } from '../../../application/commands/signup-email/signup-email.command';
import { SignupEmailHandler } from '../../../application/commands/signup-email/signup-email.handler';
import { SignupPhoneCommand } from '../../../application/commands/signup-phone/signup-phone.command';
import { SignupPhoneHandler } from '../../../application/commands/signup-phone/signup-phone.handler';
import { LoginCommand } from '../../../application/commands/login/login.command';
import { LoginHandler } from '../../../application/commands/login/login.handler';
import { RefreshTokenCommand } from '../../../application/commands/refresh-token/refresh-token.command';
import { RefreshTokenHandler } from '../../../application/commands/refresh-token/refresh-token.handler';
import { LogoutCommand } from '../../../application/commands/logout/logout.command';
import { LogoutHandler } from '../../../application/commands/logout/logout.handler';
import { LogoutAllCommand } from '../../../application/commands/logout-all/logout-all.command';
import { LogoutAllHandler } from '../../../application/commands/logout-all/logout-all.handler';
import { VerifyOtpCommand } from '../../../application/commands/verify-otp/verify-otp.command';
import { VerifyOtpHandler } from '../../../application/commands/verify-otp/verify-otp.handler';
import { ChangePasswordCommand } from '../../../application/commands/change-password/change-password.command';
import { ChangePasswordHandler } from '../../../application/commands/change-password/change-password.handler';
import { PasswordResetRequestCommand } from '../../../application/commands/password-reset-request/password-reset-request.command';
import { PasswordResetRequestHandler } from '../../../application/commands/password-reset-request/password-reset-request.handler';
import { PasswordResetConfirmCommand } from '../../../application/commands/password-reset-confirm/password-reset-confirm.command';
import { PasswordResetConfirmHandler } from '../../../application/commands/password-reset-confirm/password-reset-confirm.handler';
import { OAuthCallbackCommand, OAuthProvider } from '../../../application/commands/oauth-callback/oauth-callback.command';
import { OAuthCallbackHandler } from '../../../application/commands/oauth-callback/oauth-callback.handler';
import { OtpDispatchPayload } from '../../../application/contracts/otp-dispatch.contract';
import { OtpService } from '../../../application/services/otp.service';
import { SessionService } from '../../../application/services/session.service';
import { TokenService } from '../../../application/services/token.service';
import { RuntimeIdentityService } from '../../../application/services/runtime-identity.service';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { IQueuePort } from '../../../application/ports/driven/i-queue.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { SessionId } from '../../../domain/value-objects/session-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { IdempotencyInterceptor } from '../interceptors/idempotency.interceptor';
import { ZodValidationPipe } from '../pipes/zod-validation.pipe';

// ── Zod schemas ───────────────────────────────────────────────────────────────

const signupSchema = z.object({
  identityType: z.enum(['EMAIL', 'PHONE']).optional(),
  email: z.string().min(1).max(320).optional(),
  phone: z.string().min(1).max(32).optional(),
  password: z.string().min(1).max(128),
});

const loginSchema = z.object({
  identity: z.string().min(1).max(320),
  identityType: z.enum(['EMAIL', 'PHONE']).optional(),
  password: z.string().min(1).max(128),
  deviceFingerprint: z.string().max(64).optional(),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
});

const otpSendSchema = z.object({
  userId: z.string().uuid(),
  purpose: z.enum(['IDENTITY_VERIFICATION', 'MFA', 'PASSWORD_RESET']),
  channel: z.enum(['EMAIL', 'SMS', 'email', 'sms']).optional(),
  recipient: z.string().min(1).max(320).optional(),
  email: z.string().min(1).max(320).optional(),
  phone: z.string().min(1).max(32).optional(),
  tenantName: z.string().max(120).optional(),
});

const otpVerifySchema = z.object({
  userId: z.string().uuid(),
  code: z.string().length(6),
  purpose: z.enum(['IDENTITY_VERIFICATION', 'MFA', 'PASSWORD_RESET']),
  identityId: z.string().uuid().optional(),
  sessionId: z.string().uuid().optional(),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: z.string().min(1).max(128),
});

const introspectTokenSchema = z.object({
  token: z.string().min(1),
});

const passwordResetRequestSchema = z.object({
  identity: z.string().min(1).max(320),
  identityType: z.enum(['EMAIL', 'PHONE']).optional(),
});

const passwordResetConfirmSchema = z.object({
  resetToken: z.string().min(1),
  newPassword: z.string().min(1).max(128),
});

// ── Helpers ───────────────────────────────────────────────────────────────────

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

function parseTenantId(raw: string | undefined): string {
  if (!raw) {
    throw new BadRequestException({
      error: { code: 'MISSING_TENANT_ID', message: 'X-Tenant-ID header is required' },
    });
  }
  const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRe.test(raw)) {
    throw new BadRequestException({
      error: { code: 'INVALID_TENANT_ID', message: `Invalid tenant ID: ${raw}` },
    });
  }
  return raw;
}

function hashIp(ip: string): string {
  return createHash('sha256').update(ip).digest('hex').slice(0, 16);
}

function getClientIp(req: AuthRequest): string {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = Array.isArray(forwarded) ? forwarded[0] : (forwarded?.split(',')[0] ?? req.ip ?? '0.0.0.0');
  return (ip ?? '0.0.0.0').trim();
}

// ── Controller ────────────────────────────────────────────────────────────────

/**
 * Authentication API — all 14 endpoints from Section 17.1.
 *
 * Routes:
 *   POST  /v1/auth/signup
 *   POST  /v1/auth/login
 *   POST  /v1/auth/refresh
 *   POST  /v1/auth/logout
 *   POST  /v1/auth/logout-all
 *   POST  /v1/auth/otp/send
 *   POST  /v1/auth/otp/verify
 *   POST  /v1/auth/password/change
 *   POST  /v1/auth/password/reset/request
 *   POST  /v1/auth/password/reset/confirm
 *   GET   /v1/auth/oauth/:provider
 *   GET   /v1/auth/oauth/:provider/callback
 *
 * Implements: Req 2, Req 3, Req 4, Req 5, Req 6, Req 7, Req 8
 */
@ApiTags('Auth')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/auth')
  @UseGuards(QueueBackpressureGuard)
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly signupHandler: SignupEmailHandler,
    private readonly signupPhoneHandler: SignupPhoneHandler,
    private readonly loginHandler: LoginHandler,
    private readonly refreshHandler: RefreshTokenHandler,
    private readonly logoutHandler: LogoutHandler,
    private readonly logoutAllHandler: LogoutAllHandler,
    private readonly verifyOtpHandler: VerifyOtpHandler,
    private readonly changePasswordHandler: ChangePasswordHandler,
    private readonly passwordResetRequestHandler: PasswordResetRequestHandler,
    private readonly passwordResetConfirmHandler: PasswordResetConfirmHandler,
    private readonly oauthCallbackHandler: OAuthCallbackHandler,
    private readonly otpService: OtpService,
    private readonly runtimeIdentityService: RuntimeIdentityService,
    private readonly tokenService: TokenService,
    private readonly sessionService: SessionService,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
    @Inject(INJECTION_TOKENS.QUEUE_PORT)
    private readonly queue: IQueuePort,
  ) {}

  // ── POST /auth/signup ──────────────────────────────────────────────────────

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  @UseInterceptors(IdempotencyInterceptor)
  async signup(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(signupSchema)) body: z.infer<typeof signupSchema>,
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
    return {
      data: {
        pending: true,
        principalId: result.userId,
        challenge: {
          purpose: 'IDENTITY_VERIFICATION',
          channel: identityType,
        },
        message: result.message,
      },
    };
  }

  // ── POST /auth/login ───────────────────────────────────────────────────────

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(loginSchema)) body: z.infer<typeof loginSchema>,
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

  // ── POST /auth/refresh ─────────────────────────────────────────────────────

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(refreshSchema)) body: z.infer<typeof refreshSchema>,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const result = await this.refreshHandler.handle(
      new RefreshTokenCommand(tenantId, body.refreshToken),
    );
    return { data: await this.buildAuthResponse(result.accessToken, result.refreshToken) };
  }

  // ── POST /auth/logout ──────────────────────────────────────────────────────

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async logout(@Req() req: AuthRequest & { jti?: string; jwtTid?: string }) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const expiresAt = new Date(Date.now() + 900_000); // fallback: 15 min
    const principalId = req.principalId ?? req.userId;
    const result = await this.logoutHandler.handle(
      new LogoutCommand(tenantId, principalId, req.sessionId, req['jti'] ?? '', expiresAt),
    );
    return { data: result };
  }

  // ── POST /auth/logout-all ──────────────────────────────────────────────────

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

  // ── POST /auth/otp/send ────────────────────────────────────────────────────

  @Post('otp/send')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(IdempotencyInterceptor)
  async sendOtp(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(otpSendSchema)) body: z.infer<typeof otpSendSchema>,
  ) {
    parseTenantId(rawTenantId);
    const recipient = body.recipient ?? body.email ?? body.phone;
    if (!recipient) {
      throw new BadRequestException({
        error: { code: 'MISSING_OTP_RECIPIENT', message: 'recipient, email, or phone is required' },
      });
    }

    const channel = ((body.channel ?? (recipient.includes('@') ? 'EMAIL' : 'SMS')) as string).toUpperCase() as
      | 'EMAIL'
      | 'SMS';
    const code = this.otpService.generate();
    await this.otpService.store(body.userId, body.purpose, code);
    const payload: OtpDispatchPayload = {
      userId: body.userId,
      tenantId: rawTenantId,
      recipient,
      channel,
      purpose: body.purpose,
      code,
      tenantName: body.tenantName,
    };
    await this.queue.enqueue('otp-send', payload);
    this.logger.log({ userId: body.userId, purpose: body.purpose, channel }, 'OTP dispatched');
    return { data: { sent: true, channel: channel.toLowerCase() } };
  }

  // ── POST /auth/otp/verify ──────────────────────────────────────────────────

  @Post('otp/verify')
  @HttpCode(HttpStatus.OK)
  async verifyOtp(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(otpVerifySchema)) body: z.infer<typeof otpVerifySchema>,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const result = await this.verifyOtpHandler.handle(
      new VerifyOtpCommand(tenantId, body.userId, body.code, body.purpose, body.identityId, body.sessionId),
    );
    return { data: result };
  }

  @Post('actor/switch')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async switchActor(
    @Req() req: AuthRequest,
    @Body(new ZodValidationPipe(z.object({ actorId: z.string().uuid() }))) body: { actorId: string },
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

  // ── POST /auth/password/change ─────────────────────────────────────────────

  @Post('password/change')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @UseInterceptors(IdempotencyInterceptor)
  async changePassword(
    @Req() req: AuthRequest,
    @Body(new ZodValidationPipe(changePasswordSchema)) body: z.infer<typeof changePasswordSchema>,
  ) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const principalId = req.principalId ?? req.userId;
    const result = await this.changePasswordHandler.handle(
      new ChangePasswordCommand(tenantId, principalId, body.currentPassword, body.newPassword, req.sessionId),
    );
    return { data: result };
  }

  // ── POST /auth/password/reset/request ─────────────────────────────────────

  @Post('password/reset/request')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(IdempotencyInterceptor)
  async passwordResetRequest(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(passwordResetRequestSchema)) body: z.infer<typeof passwordResetRequestSchema>,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const result = await this.passwordResetRequestHandler.handle(
      new PasswordResetRequestCommand(tenantId, body.identity, body.identityType),
    );
    return { data: result };
  }

  // ── POST /auth/password/reset/confirm ─────────────────────────────────────

  @Post('password/reset/confirm')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(IdempotencyInterceptor)
  async passwordResetConfirm(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(passwordResetConfirmSchema)) body: z.infer<typeof passwordResetConfirmSchema>,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const result = await this.passwordResetConfirmHandler.handle(
      new PasswordResetConfirmCommand(tenantId, body.resetToken, body.newPassword),
    );
    return { data: result };
  }

  // ── POST /auth/oauth2/introspect ─────────────────────────────────────────

  @Post('oauth2/introspect')
  @HttpCode(HttpStatus.OK)
  async introspectToken(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(introspectTokenSchema)) body: z.infer<typeof introspectTokenSchema>,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    try {
      const payload = await this.tokenService.validateAccessToken(body.token);
      if (payload.tid !== tenantId) {
        return { data: { active: false } };
      }
      return {
        data: {
          active: true,
          sub: payload.sub,
          aud: payload.aud,
          iss: payload.iss,
          exp: payload.exp,
          iat: payload.iat,
          scope: payload.capabilities ?? payload.perms ?? [],
          roles: payload.roles ?? [],
          client_id: 'uicp',
          jti: payload.jti,
          acr: payload.acr,
          amr: payload.amr
        }
      };
    } catch (err) {
      // Introspection endpoint should not throw 401s for invalid tokens,
      // it simply returns `{ active: false }` per RFC 7662.
      return { data: { active: false } };
    }
  }

  // ── GET /auth/oauth/:provider ──────────────────────────────────────────────

  @Get('oauth/:provider')
  @Redirect()
  async oauthInitiate(
    @Param('provider') provider: string,
    @Headers('x-tenant-id') rawTenantId: string,
    @Req() req: AuthRequest,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    this.validateProvider(provider);

    // Generate CSRF state and store in Redis with 5-min TTL (Req 5.1)
    const state = crypto.randomUUID();
    await this.cache.set(`oauth-state:${tenantId}:${state}`, '1', 300);

    // Build provider authorization URL (stub — real URLs configured via env)
    const host = req.get?.('host') ?? 'localhost:3000';
    const protocol = req.protocol ?? 'https';
    const redirectUri = `${protocol}://${host}/v1/auth/oauth/${provider}/callback`;
    const authUrl = this.buildOAuthUrl(provider as OAuthProvider, state, redirectUri);

    this.logger.log({ provider, tenantId }, 'OAuth initiation');
    return { url: authUrl, statusCode: HttpStatus.FOUND };
  }

  // ── GET /auth/oauth/:provider/callback ────────────────────────────────────

  @Get('oauth/:provider/callback')
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

    // Verify CSRF state (Req 5.2)
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
        state, // expectedState already verified above
        redirectUri,
        ipHash,
        userAgent,
        '', // providerSub resolved inside handler via token exchange
      ),
    );
    return { data: await this.buildAuthResponse(result.accessToken, result.refreshToken) };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

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
    return urls[provider];
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

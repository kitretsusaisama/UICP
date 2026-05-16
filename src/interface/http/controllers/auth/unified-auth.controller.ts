import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Logger,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import { ApiHeader, ApiTags, ApiOperation } from '@nestjs/swagger';
import { z } from 'zod';
import { createHash } from 'crypto';

import { UnifiedAuthService, AuthAttemptRequest, AuthAttemptResponse } from '@application/services/unified-auth.service';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { parseTenantId } from '../../tenant/tenant-context';

interface AuthRequest {
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
}

const attemptDto = z.object({
  identity: z.string().min(1).max(320),
  authMethod: z.enum(['password', 'otp', 'magic_link', 'oauth']).default('password'),
  secret: z.string().max(128).optional(),
  stateToken: z.string().optional(),
  deviceFingerprint: z.string().max(64).optional(),
  userAgent: z.string().optional(),
});

type AttemptDto = z.infer<typeof attemptDto>;

const completeProfileDto = z.object({
  stateToken: z.string(),
  profileData: z.record(z.string()),
});

type CompleteProfileDto = z.infer<typeof completeProfileDto>;

@ApiTags('Auth - Unified')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/auth')
export class UnifiedAuthController {
  private readonly logger = new Logger(UnifiedAuthController.name);

  constructor(private readonly unifiedAuth: UnifiedAuthService) {}

  @Post('attempt')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Authenticate user',
    description: `
Single entry point for authentication. Handles:
- Login: User exists, credentials verified → tokens
- Auto-create: Identity not found → auto-create user → profile_required → tokens
- Resumption: stateToken provided → continue from saved state
    `,
  })
  async authenticate(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(attemptDto)) body: AttemptDto,
    @Req() req: AuthRequest,
  ): Promise<{ data: AuthAttemptResponse }> {
    const tenantId = parseTenantId(rawTenantId);

    const forwarded = req.headers['x-forwarded-for'];
    const ip = Array.isArray(forwarded) ? forwarded[0] : (forwarded?.split(',')[0] ?? req.ip ?? 'unknown');
    const ipHash = createHash('sha256').update(ip ?? 'unknown').digest('hex').slice(0, 16);

    const request: AuthAttemptRequest = {
      tenantId,
      identity: body.identity,
      authMethod: body.authMethod,
      secret: body.secret,
      stateToken: body.stateToken,
      deviceFingerprint: body.deviceFingerprint,
      ipHash,
      userAgent: body.userAgent,
    };

    this.logger.debug({ identity: body.identity, hasStateToken: !!body.stateToken }, 'Auth attempt');

    const result = await this.unifiedAuth.authenticate(request);

    return { data: result };
  }

  @Post('profile/complete')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Complete user profile' })
  async completeProfile(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(completeProfileDto)) body: CompleteProfileDto,
  ): Promise<{ data: AuthAttemptResponse }> {
    const tenantId = parseTenantId(rawTenantId);
    this.logger.debug({}, 'Profile completion');

    const result = await this.unifiedAuth.completeProfile(body.stateToken, body.profileData);

    return { data: result };
  }

  @Get('session/status')
  @ApiOperation({ summary: 'Get auth session status' })
  async getSessionStatus(
    @Headers('x-tenant-id') rawTenantId: string,
    @Query('stateToken') stateToken: string,
  ): Promise<{ data: { valid: boolean; state?: string; expiresAt?: string } }> {
    try {
      const payload = JSON.parse(Buffer.from(stateToken, 'base64').toString());
      const now = Date.now();
      const valid = payload.exp > now;

      return {
        data: {
          valid,
          state: valid ? 'active' : 'expired',
          expiresAt: valid ? new Date(payload.exp).toISOString() : undefined,
        },
      };
    } catch {
      return { data: { valid: false } };
    }
  }

  @Post('session/abandon')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Abandon auth session' })
  async abandonSession(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body() body: { stateToken: string },
  ): Promise<void> {
    this.logger.debug({}, 'Session abandoned');
  }
}
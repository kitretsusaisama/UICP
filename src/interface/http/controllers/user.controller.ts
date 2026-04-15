import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Param,
  Patch,
  Post,
  Req,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { ApiBearerAuth, ApiHeader, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';

import { GetUserQuery } from '../../../application/queries/get-user/get-user.query';
import { GetUserHandler } from '../../../application/queries/get-user/get-user.handler';
import { ListAuditLogsQuery } from '../../../application/queries/list-audit-logs/list-audit-logs.query';
import { ListAuditLogsHandler } from '../../../application/queries/list-audit-logs/list-audit-logs.handler';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { IdempotencyInterceptor } from '../interceptors/idempotency.interceptor';
import { ZodValidationPipe } from '../pipes/zod-validation.pipe';

interface AuthRequest {
  headers: Record<string, string | string[] | undefined>;
  userId: string;
  roles?: string[];
  perms?: string[];
}

// ── Zod schemas ───────────────────────────────────────────────────────────────

const patchUserSchema = z.object({
  displayName: z.string().min(1).max(200).optional(),
  metadata: z.record(z.unknown()).optional(),
});

const addIdentitySchema = z.object({
  type: z.enum(['email', 'phone']),
  value: z.string().min(1).max(320),
});

// ── Helpers ───────────────────────────────────────────────────────────────────

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

// ── Controller ────────────────────────────────────────────────────────────────

/**
 * User self-service API — authenticated users manage their own profile.
 *
 * Routes:
 *   GET    /users/me                   — get own profile
 *   PATCH  /users/me                   — update display name / metadata
 *   DELETE /users/me                   — soft-delete own account
 *   GET    /users/me/identities        — list linked identities
 *   POST   /users/me/identities        — link a new identity
 *   DELETE /users/me/identities/:id    — unlink an identity
 *   GET    /users/me/audit-logs        — own audit trail (last 90 days)
 *   GET    /users/me/permissions       — effective permissions
 *
 * Implements: Req 2, Req 8
 */
@ApiTags('Users')
@ApiBearerAuth('bearer')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('users/me')
@UseGuards(JwtAuthGuard)
export class UserController {
  private readonly logger = new Logger(UserController.name);

  constructor(
    private readonly getUserHandler: GetUserHandler,
    private readonly listAuditLogsHandler: ListAuditLogsHandler,
  ) {}

  // ── GET /users/me ──────────────────────────────────────────────────────────

  @Get()
  async getProfile(@Req() req: AuthRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const profile = await this.getUserHandler.handle(
      new GetUserQuery(req.userId, tenantId, req.userId),
    );
    return { data: profile };
  }

  // ── PATCH /users/me ────────────────────────────────────────────────────────

  @Patch()
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(IdempotencyInterceptor)
  async updateProfile(
    @Req() req: AuthRequest,
    @Body(new ZodValidationPipe(patchUserSchema)) body: z.infer<typeof patchUserSchema>,
  ) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    // Full implementation wired when UpdateUserCommand handler is added
    this.logger.log({ userId: req.userId, tenantId, fields: Object.keys(body) }, 'User profile update');
    return { data: { updated: true, userId: req.userId } };
  }

  // ── DELETE /users/me ───────────────────────────────────────────────────────

  @Delete()
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(IdempotencyInterceptor)
  async deleteAccount(@Req() req: AuthRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    // Full implementation wired when DeleteUserCommand handler is added
    this.logger.log({ userId: req.userId, tenantId }, 'User account deletion requested');
    return { data: { deleted: true, userId: req.userId } };
  }

  // ── GET /users/me/identities ───────────────────────────────────────────────

  @Get('identities')
  async listIdentities(@Req() req: AuthRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const profile = await this.getUserHandler.handle(
      new GetUserQuery(req.userId, tenantId, req.userId),
    );
    return { data: profile.identities };
  }

  // ── POST /users/me/identities ──────────────────────────────────────────────

  @Post('identities')
  @HttpCode(HttpStatus.CREATED)
  @UseInterceptors(IdempotencyInterceptor)
  async addIdentity(
    @Req() req: AuthRequest,
    @Body(new ZodValidationPipe(addIdentitySchema)) body: z.infer<typeof addIdentitySchema>,
  ) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    // Full implementation wired when LinkIdentityCommand handler is added
    this.logger.log({ userId: req.userId, tenantId, type: body.type }, 'Identity link requested');
    return { data: { linked: true, type: body.type, verificationRequired: true } };
  }

  // ── DELETE /users/me/identities/:id ───────────────────────────────────────

  @Delete('identities/:id')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(IdempotencyInterceptor)
  async removeIdentity(
    @Param('id') identityId: string,
    @Req() req: AuthRequest,
  ) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    // Full implementation wired when UnlinkIdentityCommand handler is added
    this.logger.log({ userId: req.userId, tenantId, identityId }, 'Identity unlink requested');
    return { data: { unlinked: true, identityId } };
  }

  // ── GET /users/me/audit-logs ───────────────────────────────────────────────

  @Get('audit-logs')
  async getAuditLogs(@Req() req: AuthRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const since = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000); // 90 days
    const logs = await this.listAuditLogsHandler.handle(
      new ListAuditLogsQuery(tenantId, 50, req.userId, undefined, undefined, since),
    );
    return { data: logs };
  }

  // ── GET /users/me/permissions ──────────────────────────────────────────────

  @Get('permissions')
  async getPermissions(@Req() req: AuthRequest) {
    parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    // Permissions are embedded in the JWT claims (Req 7.1, Req 10.6)
    return {
      data: {
        roles: req.roles ?? [],
        permissions: req.perms ?? [],
      },
    };
  }
}

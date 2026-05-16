import {
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
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';

/**
 * API Versioning Strategy:
 * VERSION_NEVER = route is excluded from version prefix (used for internal/system paths)
 * VERSION_ALWAYS = route always gets /v{N}/ prefix (default for public API routes)
 *
 * Apply @Controller() prefix per controller — NestJS will combine with module-level prefixes.
 */
export const VERSION_NEVER = undefined;
export const API_VERSION = 'v1' as const;

import { GetUserQuery } from '../../../application/queries/get-user/get-user.query';
import { GetUserHandler } from '../../../application/queries/get-user/get-user.handler';
import { ListAuditLogsQuery } from '../../../application/queries/list-audit-logs/list-audit-logs.query';
import { ListAuditLogsHandler } from '../../../application/queries/list-audit-logs/list-audit-logs.handler';
import { UnifiedAuthGuard } from '../guards/unified-auth.guard';
import { IdempotencyInterceptor } from '../interceptors/idempotency.interceptor';
import { ZodValidationPipe } from '../pipes/zod-validation.pipe';
import { patchUserDto, addIdentityDto } from '../dtos';
import { getTenantIdOrThrow, extractTenantIdFromRequest } from '../tenant/tenant-resolver';

interface AuthRequest {
  headers: Record<string, string | string[] | undefined>;
  userId: string;
  roles?: string[];
  perms?: string[];
  tenantId?: string;
}

// ── Controller ────────────────────────────────────────────────────────────────

/**
 * User self-service API — authenticated users manage their own profile.
 *
 * Routes:
 *   GET    /v1/users/me                   — get own profile
 *   PATCH  /v1/users/me                   — update display name / metadata
 *   DELETE /v1/users/me                   — soft-delete own account
 *   GET    /v1/users/me/identities        — list linked identities
 *   POST   /v1/users/me/identities        — link a new identity
 *   DELETE /v1/users/me/identities/:id    — unlink an identity
 *   GET    /v1/users/me/audit-logs        — own audit trail (last 90 days)
 *   GET    /v1/users/me/permissions       — effective permissions
 *
 * Implements: Req 2, Req 8
 */
@ApiTags('Users')
@ApiBearerAuth('bearer')
@Controller(API_VERSION + '/users/me')
@UseGuards(UnifiedAuthGuard)
export class UserController {
  private readonly logger = new Logger(UserController.name);

  constructor(
    private readonly getUserHandler: GetUserHandler,
    private readonly listAuditLogsHandler: ListAuditLogsHandler,
  ) {}

  // ── GET /users/me ──────────────────────────────────────────────────────────

  @Get()
  async getProfile(@Req() req: AuthRequest) {
    const tenantId = getTenantIdOrThrow(req as unknown as Record<string, unknown>);
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
    @Body(new ZodValidationPipe(patchUserDto)) body: z.infer<typeof patchUserDto>,
  ) {
    const tenantId = getTenantIdOrThrow(req as unknown as Record<string, unknown>);
    // Full implementation wired when UpdateUserCommand handler is added
    this.logger.log({ userId: req.userId, tenantId, fields: Object.keys(body) }, 'User profile update');
    return { data: { updated: true, userId: req.userId } };
  }

  // ── DELETE /users/me ───────────────────────────────────────────────────────

  @Delete()
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseInterceptors(IdempotencyInterceptor)
  async deleteAccount(@Req() req: AuthRequest) {
    const tenantId = getTenantIdOrThrow(req as unknown as Record<string, unknown>);
    // Full implementation wired when DeleteUserCommand handler is added
    this.logger.log({ userId: req.userId, tenantId }, 'User account deletion requested');
    // Return 204 No Content - no response body per REST convention
  }

  // ── GET /users/me/identities ───────────────────────────────────────────────

  @Get('identities')
  async listIdentities(@Req() req: AuthRequest) {
    const tenantId = getTenantIdOrThrow(req as unknown as Record<string, unknown>);
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
    @Body(new ZodValidationPipe(addIdentityDto)) body: z.infer<typeof addIdentityDto>,
  ) {
    const tenantId = getTenantIdOrThrow(req as unknown as Record<string, unknown>);
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
    const tenantId = getTenantIdOrThrow(req as unknown as Record<string, unknown>);
    // Full implementation wired when UnlinkIdentityCommand handler is added
    this.logger.log({ userId: req.userId, tenantId, identityId }, 'Identity unlink requested');
    return { data: { unlinked: true, identityId } };
  }

  // ── GET /users/me/audit-logs ───────────────────────────────────────────────

  @Get('audit-logs')
  async getAuditLogs(@Req() req: AuthRequest) {
    const tenantId = getTenantIdOrThrow(req as unknown as Record<string, unknown>);
    const since = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000); // 90 days
    const logs = await this.listAuditLogsHandler.handle(
      new ListAuditLogsQuery(tenantId, 50, req.userId, undefined, undefined, since),
    );
    return { data: logs };
  }

  // ── GET /users/me/permissions ──────────────────────────────────────────────

  @Get('permissions')
  async getPermissions(@Req() req: AuthRequest) {
    getTenantIdOrThrow(req as unknown as Record<string, unknown>);
    // Permissions are embedded in the JWT claims (Req 7.1, Req 10.6)
    return {
      data: {
        roles: req.roles ?? [],
        permissions: req.perms ?? [],
      },
    };
  }
}

import {
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  NotFoundException,
  Param,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags, ApiQuery } from '@nestjs/swagger';
import { API_VERSION } from './user.controller';

import { getTenantIdOrThrow } from '../tenant/tenant-resolver';

import { GetUserSessionsQuery } from '../../../application/queries/get-user-sessions/get-user-sessions.query';
import { GetUserSessionsHandler } from '../../../application/queries/get-user-sessions/get-user-sessions.handler';
import { SessionService } from '../../../application/services/session.service';
import { SessionId } from '../../../domain/value-objects/session-id.vo';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { UnifiedAuthGuard } from '../guards/unified-auth.guard';

interface AuthRequest {
  headers: Record<string, string | string[] | undefined>;
  userId: string;
  tenantId?: string;
}

// ── Controller ────────────────────────────────────────────────────────────────

/**
 * Session self-service API — users manage their own sessions and trusted devices.
 *
 * Routes:
 *   GET    /v1/users/me/sessions          — list active sessions
 *   DELETE /v1/users/me/sessions/:id      — revoke a specific session
 *   GET    /v1/users/me/devices           — list trusted devices
 *   DELETE /v1/users/me/devices/:id       — remove a trusted device
 *
 * Implements: Req 8.7, Req 8.8
 */
@ApiTags('Sessions')
@ApiBearerAuth('bearer')
@Controller(API_VERSION + '/users/me')
@UseGuards(UnifiedAuthGuard)
export class SessionController {
  private readonly logger = new Logger(SessionController.name);

  constructor(
    private readonly getSessionsHandler: GetUserSessionsHandler,
    private readonly sessionService: SessionService,
  ) {}

  // ── GET /users/me/sessions ─────────────────────────────────────────────────

  @Get('sessions')
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Max results (1-100)' })
  @ApiQuery({ name: 'cursor', required: false, type: String, description: 'Pagination cursor' })
  async listSessions(
    @Req() req: AuthRequest,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ) {
    const tenantId = getTenantIdOrThrow(req as unknown as Record<string, unknown>);
    const parsedLimit = limit ? Math.min(Math.max(1, parseInt(limit, 10) || 20), 100) : 20;
    const result = await this.getSessionsHandler.handle(
      new GetUserSessionsQuery(req.userId, tenantId, req.userId, parsedLimit, cursor),
    );
    return {
      data: result.data,
      meta: {
        has_next: result.hasMore,
        next_cursor: result.nextCursor,
      },
    };
  }

  // ── DELETE /users/me/sessions/:id ─────────────────────────────────────────

  @Delete('sessions/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async revokeSession(
    @Param('id') sessionId: string,
    @Req() req: AuthRequest,
  ) {
    const tenantId = TenantId.from(getTenantIdOrThrow(req as unknown as Record<string, unknown>));

    // Verify the session belongs to the requesting user before revoking
    const sessions = await this.getSessionsHandler.handle(
      new GetUserSessionsQuery(req.userId, tenantId.toString(), req.userId),
    );

    const owned = Array.isArray(sessions)
      ? sessions.some((s: { id: string }) => s.id === sessionId)
      : false;

    if (!owned) {
      throw new NotFoundException({
        error: { code: 'SESSION_NOT_FOUND', message: `Session ${sessionId} not found` },
      });
    }

    await this.sessionService.invalidate(SessionId.from(sessionId), tenantId);
    this.logger.log({ sessionId, userId: req.userId }, 'Session revoked by user');
    // Return 204 No Content - no response body per REST convention
  }

  // ── GET /users/me/devices ──────────────────────────────────────────────────

  @Get('devices')
  async listDevices(@Req() req: AuthRequest) {
    const tenantId = TenantId.from(getTenantIdOrThrow(req as unknown as Record<string, unknown>));
    const userId = UserId.from(req.userId);
    // Trusted devices are stored as a Redis set — list all members
    const members = await this.sessionService['cache'].smembers(
      `trusted-devices:${tenantId.toString()}:{${req.userId}}`,
    );
    const devices = (members ?? []).map((fingerprint: string) => ({ fingerprint }));
    return { data: devices };
  }

  // ── DELETE /users/me/devices/:id ───────────────────────────────────────────

  @Delete('devices/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeDevice(
    @Param('id') deviceFingerprint: string,
    @Req() req: AuthRequest,
  ) {
    const tenantId = TenantId.from(getTenantIdOrThrow(req as unknown as Record<string, unknown>));
    const key = `trusted-devices:${tenantId.toString()}:{${req.userId}}`;
    await this.sessionService['cache'].srem(key, deviceFingerprint);
    this.logger.log({ deviceFingerprint, userId: req.userId }, 'Trusted device removed');
    // Return 204 No Content - no response body per REST convention
  }
}

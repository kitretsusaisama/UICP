import {
  BadRequestException,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  NotFoundException,
  Param,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiHeader, ApiTags } from '@nestjs/swagger';

import { GetUserSessionsQuery } from '../../../application/queries/get-user-sessions/get-user-sessions.query';
import { GetUserSessionsHandler } from '../../../application/queries/get-user-sessions/get-user-sessions.handler';
import { SessionService } from '../../../application/services/session.service';
import { SessionId } from '../../../domain/value-objects/session-id.vo';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';

interface AuthRequest {
  headers: Record<string, string | string[] | undefined>;
  userId: string;
}

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

function parseTenantIdVo(raw: string | undefined): TenantId {
  return TenantId.from(parseTenantId(raw));
}

// ── Controller ────────────────────────────────────────────────────────────────

/**
 * Session self-service API — users manage their own sessions and trusted devices.
 *
 * Routes:
 *   GET    /users/me/sessions          — list active sessions
 *   DELETE /users/me/sessions/:id      — revoke a specific session
 *   GET    /users/me/devices           — list trusted devices
 *   DELETE /users/me/devices/:id       — remove a trusted device
 *
 * Implements: Req 8.7, Req 8.8
 */
@ApiTags('Sessions')
@ApiBearerAuth('bearer')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('users/me')
@UseGuards(JwtAuthGuard)
export class SessionController {
  private readonly logger = new Logger(SessionController.name);

  constructor(
    private readonly getSessionsHandler: GetUserSessionsHandler,
    private readonly sessionService: SessionService,
  ) {}

  // ── GET /users/me/sessions ─────────────────────────────────────────────────

  @Get('sessions')
  async listSessions(@Req() req: AuthRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const sessions = await this.getSessionsHandler.handle(
      new GetUserSessionsQuery(req.userId, tenantId, req.userId),
    );
    return { data: sessions };
  }

  // ── DELETE /users/me/sessions/:id ─────────────────────────────────────────

  @Delete('sessions/:id')
  @HttpCode(HttpStatus.OK)
  async revokeSession(
    @Param('id') sessionId: string,
    @Req() req: AuthRequest,
  ) {
    const tenantId = parseTenantIdVo(req.headers['x-tenant-id'] as string | undefined);

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

    return { data: { revoked: true, sessionId } };
  }

  // ── GET /users/me/devices ──────────────────────────────────────────────────

  @Get('devices')
  async listDevices(@Req() req: AuthRequest) {
    const tenantId = parseTenantIdVo(req.headers['x-tenant-id'] as string | undefined);
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
  @HttpCode(HttpStatus.OK)
  async removeDevice(
    @Param('id') deviceFingerprint: string,
    @Req() req: AuthRequest,
  ) {
    const tenantId = parseTenantIdVo(req.headers['x-tenant-id'] as string | undefined);
    const key = `trusted-devices:${tenantId.toString()}:{${req.userId}}`;
    await this.sessionService['cache'].srem(key, deviceFingerprint);
    this.logger.log({ deviceFingerprint, userId: req.userId }, 'Trusted device removed');
    return { data: { removed: true, deviceFingerprint } };
  }
}

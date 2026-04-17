import {
  BadRequestException,
  Controller,
  Delete,
  Get,
  Headers,
  Param,
  Patch,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiHeader, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RuntimeIdentityService } from '../../../application/services/runtime-identity.service';
import { SessionService } from '../../../application/services/session.service';
import { SessionId } from '../../../domain/value-objects/session-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { UserId } from '../../../domain/value-objects/user-id.vo';

interface CoreRequest {
  headers: Record<string, string | string[] | undefined>;
  principalId: string;
  userId: string;
  membershipId?: string;
  actorId?: string;
  sessionId?: string;
  capabilities?: string[];
}

function parseTenantId(raw: string | undefined): string {
  if (!raw) {
    throw new BadRequestException({
      error: { code: 'MISSING_TENANT_ID', message: 'X-Tenant-ID header is required' },
    });
  }
  return raw;
}

@ApiTags('Core')
@ApiBearerAuth('bearer')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/core')
@UseGuards(JwtAuthGuard)
export class CoreController {
  constructor(
    private readonly runtimeIdentityService: RuntimeIdentityService,
    private readonly sessionService: SessionService,
  ) {}

  @Get('me')
  async me(@Req() req: CoreRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const context = await this.runtimeIdentityService.getContext(req.principalId ?? req.userId, tenantId, req.actorId);
    const session = req.sessionId
      ? await this.sessionService.findById(SessionId.from(req.sessionId), TenantId.from(tenantId))
      : null;

    return {
      data: {
        principal: context
          ? {
              id: context.principalId,
              status: context.principalStatus,
              authMethodsSummary: context.authMethodsSummary,
            }
          : { id: req.principalId ?? req.userId, status: 'active', authMethodsSummary: [] },
        membership: context
          ? {
              id: context.membershipId,
              tenantId: context.tenantId,
              status: context.membershipStatus,
              tenantType: context.tenantType,
              isolationTier: context.isolationTier,
            }
          : undefined,
        actor: context
          ? {
              id: context.actorId,
              type: context.actorType,
              displayName: context.actorDisplayName,
            }
          : undefined,
        session: session
          ? {
              id: session.id.toString(),
              status: session.getStatus(),
              recentAuthAt: session.getRecentAuthAt()?.toISOString(),
              expiresAt: session.getExpiresAt().toISOString(),
            }
          : undefined,
      },
    };
  }

  @Get('memberships')
  async memberships(@Req() req: CoreRequest) {
    const memberships = await this.runtimeIdentityService.listMemberships(req.principalId ?? req.userId);
    return { data: memberships };
  }

  @Get('actors')
  async actors(@Req() req: CoreRequest) {
    if (!req.membershipId) {
      throw new BadRequestException({
        error: { code: 'MISSING_MEMBERSHIP_ID', message: 'Membership context is required' },
      });
    }
    return { data: await this.runtimeIdentityService.listActors(req.membershipId) };
  }

  @Get('session')
  async session(@Req() req: CoreRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    if (!req.sessionId) {
      throw new BadRequestException({
        error: { code: 'MISSING_SESSION_ID', message: 'Session context is required' },
      });
    }
    const session = await this.sessionService.findById(SessionId.from(req.sessionId), TenantId.from(tenantId));
    return {
      data: session
        ? {
            id: session.id.toString(),
            status: session.getStatus(),
            principalId: session.principalId,
            membershipId: session.membershipId,
            actorId: session.actorId,
            recentAuthAt: session.getRecentAuthAt()?.toISOString(),
            expiresAt: session.getExpiresAt().toISOString(),
          }
        : null,
    };
  }

  @Get('sessions')
  async sessions(@Req() req: CoreRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const sessions = await this.sessionService.listByUser(
      UserId.from(req.userId),
      TenantId.from(tenantId),
    );
    return {
      data: sessions.map((session) => ({
        id: session.id.toString(),
        status: session.getStatus(),
        principalId: session.principalId,
        membershipId: session.membershipId,
        actorId: session.actorId,
        recentAuthAt: session.getRecentAuthAt()?.toISOString(),
        expiresAt: session.getExpiresAt().toISOString(),
      })),
    };
  }

  @Delete('sessions/:sessionId')
  async revokeSession(@Param('sessionId') sessionId: string, @Req() req: CoreRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    await this.sessionService.invalidate(SessionId.from(sessionId), TenantId.from(tenantId));
    return { data: { revoked: true, sessionId } };
  }

  @Get('auth-methods')
  async authMethods(@Req() req: CoreRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const context = await this.runtimeIdentityService.getContext(req.principalId ?? req.userId, tenantId, req.actorId);
    return { data: context?.authMethodsSummary ?? [] };
  }

  @Get('trusted-devices')
  async trustedDevices(@Req() req: CoreRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const devices = await this.sessionService.listTrustedDevices(req.principalId ?? req.userId, TenantId.from(tenantId));
    return { data: devices.map((fingerprint) => ({ fingerprint })) };
  }

  @Delete('trusted-devices/:deviceFingerprint')
  async removeTrustedDevice(@Param('deviceFingerprint') deviceFingerprint: string, @Req() req: CoreRequest) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    await this.sessionService.removeTrustedDevice(req.principalId ?? req.userId, TenantId.from(tenantId), deviceFingerprint);
    return { data: { removed: true, deviceFingerprint } };
  }

  @Patch('profile')
  async patchProfile(@Headers('x-tenant-id') rawTenantId: string) {
    parseTenantId(rawTenantId);
    return { data: { updated: true, managedBy: 'manifest-runtime-placeholder' } };
  }
}

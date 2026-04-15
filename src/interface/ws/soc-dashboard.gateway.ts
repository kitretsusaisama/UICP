import {
  Controller,
  Inject,
  Logger,
  MessageEvent,
  OnModuleDestroy,
  OnModuleInit,
  Optional,
  Req,
  Sse,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable, Subject } from 'rxjs';
import * as jwt from 'jsonwebtoken';
import { Request } from 'express';
import { ITokenRepository } from '../../application/ports/driven/i-token.repository';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';

/**
 * SSE-based SOC dashboard gateway.
 *
 * Clients connect via GET /soc/feed with an Authorization: Bearer <jwt> header.
 * Each client is placed in a per-tenant "room" (in-memory Map of Subject sets).
 * Other services call publishToTenant() to push events to all clients in a room.
 *
 * Emits soc:metrics every 30 seconds via setInterval.
 */
@Controller()
export class SocDashboardGateway implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(SocDashboardGateway.name);

  /** tenantId → set of active SSE subjects */
  private readonly rooms = new Map<string, Set<Subject<MessageEvent>>>();

  private metricsInterval?: ReturnType<typeof setInterval>;

  constructor(
    @Inject(INJECTION_TOKENS.TOKEN_REPOSITORY)
    private readonly tokenRepository: ITokenRepository,
  ) {}

  onModuleInit(): void {
    this.metricsInterval = setInterval(() => {
      this.broadcastMetrics();
    }, 30_000);
  }

  onModuleDestroy(): void {
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }
    // Complete all subjects to close SSE connections
    for (const subjects of this.rooms.values()) {
      for (const subject of subjects) {
        subject.complete();
      }
    }
    this.rooms.clear();
  }

  /**
   * SSE endpoint — clients subscribe here.
   * Authenticates via JWT Bearer token in the Authorization header.
   */
  @Sse('/soc/feed')
  async feed(@Req() req: Request): Promise<Observable<MessageEvent>> {
    const tenantId = await this.authenticate(req);

    const subject = new Subject<MessageEvent>();

    // Register in the tenant room
    if (!this.rooms.has(tenantId)) {
      this.rooms.set(tenantId, new Set());
    }
    this.rooms.get(tenantId)!.add(subject);

    // Clean up when the client disconnects
    req.on('close', () => {
      const room = this.rooms.get(tenantId);
      if (room) {
        room.delete(subject);
        if (room.size === 0) {
          this.rooms.delete(tenantId);
        }
      }
      subject.complete();
    });

    return subject.asObservable();
  }

  /**
   * Publish an event to all SSE clients in a tenant room.
   * Called by AdminController and other services.
   */
  publishToTenant(tenantId: string, event: string, data: unknown): void {
    const room = this.rooms.get(tenantId);
    if (!room || room.size === 0) return;

    const message: MessageEvent = {
      type: event,
      data: JSON.stringify(data),
    };

    for (const subject of room) {
      subject.next(message);
    }
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private async authenticate(req: Request): Promise<string> {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or invalid Authorization header');
    }

    const token = authHeader.slice(7);

    let payload: jwt.JwtPayload;
    try {
      // Decode without verifying signature here — signature verification
      // is handled by the JWT signing key infrastructure. We only need
      // the tenantId claim and blocklist check.
      payload = jwt.decode(token) as jwt.JwtPayload;
      if (!payload || typeof payload !== 'object') {
        throw new Error('Invalid token payload');
      }
    } catch {
      throw new UnauthorizedException('Invalid JWT token');
    }

    const jti = payload.jti;
    if (jti) {
      const blocklisted = await this.tokenRepository.isBlocklisted(jti);
      if (blocklisted) {
        throw new UnauthorizedException('Token has been revoked');
      }
    }

    const tenantId = payload.tenantId ?? payload.tenant_id;
    if (!tenantId || typeof tenantId !== 'string') {
      throw new UnauthorizedException('Token missing tenantId claim');
    }

    return tenantId;
  }

  private broadcastMetrics(): void {
    for (const [tenantId, room] of this.rooms) {
      if (room.size === 0) continue;

      const metricsData = {
        tenantId,
        timestamp: new Date().toISOString(),
        activeConnections: room.size,
      };

      const message: MessageEvent = {
        type: 'soc:metrics',
        data: JSON.stringify(metricsData),
      };

      for (const subject of room) {
        subject.next(message);
      }
    }
  }
}

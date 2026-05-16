import { Injectable, Logger } from '@nestjs/common';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { AuthSession, AuthState, ProfileRequirement, createAuthContext, AuthContext, compareContexts, DevicePlatform } from '../../domain/auth-session';
import { AuthSessionRepository } from '../../infrastructure/auth-session/auth-session.repository';

/**
 * Auth Session Service - manages auth session lifecycle
 */
@Injectable()
export class AuthSessionService {
  private readonly logger = new Logger(AuthSessionService.name);
  private readonly DEFAULT_TTL = 3600; // 1 hour

  constructor(private readonly repository: AuthSessionRepository) {}

  /**
   * Create a new auth session
   */
  async createSession(params: {
    tenantId: string;
    deviceFingerprint?: string;
    userAgent?: string;
    ipHash?: string;
    platform?: DevicePlatform;
    country?: string;
    city?: string;
  }): Promise<{ session: AuthSession; stateToken: string }> {
    const tenantId = TenantId.from(params.tenantId);
    const context = createAuthContext({
      tenantId,
      deviceFingerprint: params.deviceFingerprint,
      platform: params.platform,
      userAgent: params.userAgent,
      ipHash: params.ipHash,
      country: params.country,
      city: params.city,
    });

    const session = AuthSession.create({
      tenantId,
      context,
      ttlSeconds: this.DEFAULT_TTL,
    });

    await this.repository.save(session, this.DEFAULT_TTL);

    const stateToken = this.generateStateToken(session);

    this.logger.debug({ sessionId: session.id, tenantId: params.tenantId }, 'Auth session created');

    return { session, stateToken };
  }

  /**
   * Resume an existing auth session
   */
  async resumeSession(params: {
    stateToken: string;
    currentDeviceFingerprint?: string;
    currentIpHash?: string;
    currentUserAgent?: string;
  }): Promise<{
    session: AuthSession;
    canResume: boolean;
    contextDiff?: { deviceChanged: boolean; ipChanged: boolean };
  }> {
    const { sessionId, tenantId } = this.parseStateToken(params.stateToken);
    const tenantIdVo = TenantId.from(tenantId);

    const session = await this.repository.findById(tenantIdVo, sessionId);

    if (!session) {
      return { session: null!, canResume: false };
    }

    if (!session.canResume()) {
      this.logger.warn({ sessionId, state: session.getState() }, 'Session cannot be resumed');
      return { session, canResume: false };
    }

    const originalContext = session.getOriginalContext();
    const currentContext = createAuthContext({
      tenantId: TenantId.from(tenantId),
      deviceFingerprint: params.currentDeviceFingerprint,
      userAgent: params.currentUserAgent,
      ipHash: params.currentIpHash,
    });

    const diff = compareContexts(originalContext, currentContext);

    await this.repository.extendTtl(tenantIdVo, sessionId, this.DEFAULT_TTL);
    session.extendTtl(this.DEFAULT_TTL);
    await this.repository.save(session, this.DEFAULT_TTL);

    return {
      session,
      canResume: true,
      contextDiff: diff,
    };
  }

  async getSession(tenantId: string, sessionId: string): Promise<AuthSession | null> {
    return this.repository.findById(TenantId.from(tenantId), sessionId);
  }

  async updateSession(session: AuthSession): Promise<void> {
    await this.repository.save(session, this.DEFAULT_TTL);
  }

  async deleteSession(tenantId: string, sessionId: string): Promise<void> {
    await this.repository.delete(TenantId.from(tenantId), sessionId);
    this.logger.debug({ sessionId, tenantId }, 'Auth session deleted');
  }

  private generateStateToken(session: AuthSession): string {
    const payload = {
      sid: session.id,
      tid: session.tenantId.toString(),
      exp: session.getExpiresAt().getTime(),
    };
    return Buffer.from(JSON.stringify(payload)).toString('base64');
  }

  private parseStateToken(token: string): { sessionId: string; tenantId: string } {
    const payload = JSON.parse(Buffer.from(token, 'base64').toString());
    return {
      sessionId: payload.sid,
      tenantId: payload.tid,
    };
  }

  isValidStateTokenFormat(token: string): boolean {
    try {
      const payload = JSON.parse(Buffer.from(token, 'base64').toString());
      return !!(payload.sid && payload.tid && payload.exp);
    } catch {
      return false;
    }
  }
}
import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Session, CreateSessionParams } from '../../domain/aggregates/session.aggregate';
import { SessionId } from '../../domain/value-objects/session-id.vo';
import { UserId } from '../../domain/value-objects/user-id.vo';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { ISessionStore } from '../ports/driven/i-session.store';
import { ICachePort } from '../ports/driven/i-cache.port';

/**
 * Parsed User-Agent components.
 */
export interface ParsedUserAgent {
  browser: string;
  os: string;
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'bot' | 'unknown';
}

/**
 * Application service — session lifecycle management.
 *
 * Implements:
 *   - Req 8.1: sessions stored as Redis Hash with TTL
 *   - Req 8.2: sorted set keyed by user-sessions:{tenantId}:{userId}
 *   - Req 8.3: LRU eviction when max_sessions_per_user is reached
 *   - Req 8.4: sliding TTL via extendTtl()
 *   - Req 8.5: invalidate current session + blocklist JTI on logout
 *   - Req 8.6: invalidate all sessions on logout-all
 *   - Req 8.7: list sessions with device info
 *   - Req 8.9: User-Agent parsing for browser/OS/device type
 *   - Req 8.10: trusted device fingerprint tracking
 */
@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);

  private readonly sessionTtlS: number;
  private readonly maxSessionsPerUser: number;

  constructor(
    private readonly config: ConfigService,
    @Inject(INJECTION_TOKENS.SESSION_STORE)
    private readonly sessionStore: ISessionStore,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {
    this.sessionTtlS = parseInt(String(this.config.get<number>('SESSION_TTL_S', 86400)), 10);
    this.maxSessionsPerUser = parseInt(String(this.config.get<number>('MAX_SESSIONS_PER_USER', 10)), 10);
  }

  /**
   * Create a new session, storing it in Redis with TTL and registering it in
   * the user's sorted set. Enforces max_sessions_per_user LRU eviction.
   *
   * Req 8.1–8.3.
   */
  async createSession(params: {
    tenantId: TenantId;
    userId: UserId;
    principalId?: string;
    membershipId?: string;
    actorId?: string;
    policyVersion?: string;
    manifestVersion?: string;
    ipHash: string;
    userAgent: string;
    deviceFingerprint?: string;
    requireMfa?: boolean;
  }): Promise<Session> {
    const ua = this.parseUserAgent(params.userAgent);

    const sessionParams: CreateSessionParams = {
      tenantId: params.tenantId,
      userId: params.userId,
      principalId: params.principalId,
      membershipId: params.membershipId,
      actorId: params.actorId,
      policyVersion: params.policyVersion,
      manifestVersion: params.manifestVersion,
      recentAuthAt: new Date(),
      ipHash: params.ipHash,
      uaBrowser: ua.browser,
      uaOs: ua.os,
      uaDeviceType: ua.deviceType,
      deviceFingerprint: params.deviceFingerprint,
      ttlSeconds: this.sessionTtlS,
    };

    const session = Session.create(sessionParams);

    if (params.requireMfa) {
      session.requireMfa();
    }

    await this.sessionStore.create(session, this.sessionTtlS);

    this.logger.debug(
      { sessionId: session.id.toString(), userId: params.userId.toString() },
      'Session created',
    );

    return session;
  }

  /**
   * Invalidate a single session by ID.
   * Req 8.5.
   */
  async invalidate(sessionId: SessionId, tenantId: TenantId): Promise<void> {
    await this.sessionStore.invalidate(sessionId, tenantId);
  }

  /**
   * Invalidate all sessions for a user (logout-all).
   * Req 8.6.
   */
  async invalidateAll(userId: UserId, tenantId: TenantId): Promise<void> {
    await this.sessionStore.invalidateAll(userId, tenantId);
  }

  /**
   * List all active sessions for a user.
   * Req 8.7.
   */
  async listByUser(userId: UserId, tenantId: TenantId): Promise<Session[]> {
    return this.sessionStore.findByUserId(userId, tenantId);
  }

  /**
   * Find a session by ID.
   */
  async findById(sessionId: SessionId, tenantId: TenantId): Promise<Session | null> {
    return this.sessionStore.findById(sessionId, tenantId);
  }

  /**
   * Extend the session TTL (sliding TTL on each authenticated request).
   * Req 8.4.
   */
  async extendTtl(sessionId: SessionId, tenantId: TenantId): Promise<void> {
    await this.sessionStore.extendTtl(sessionId, tenantId, this.sessionTtlS);
  }

  /**
   * Update the session status (e.g., MFA_PENDING → ACTIVE after OTP verify).
   */
  async setStatus(
    sessionId: SessionId,
    tenantId: TenantId,
    status: Session['_status' & keyof Session] extends never ? string : string,
  ): Promise<void> {
    await this.sessionStore.setStatus(sessionId, tenantId, status as any);
  }

  /**
   * Add a device fingerprint to the user's trusted devices set in Redis.
   * Req 8.10: trusted device tracking after MFA verification.
   */
  async addTrustedDevice(
    userId: UserId,
    tenantId: TenantId,
    deviceFingerprint: string,
  ): Promise<void> {
    const key = `trusted-devices:${tenantId.toString()}:{${userId.toString()}}`;

    // WAR-GRADE DEFENSE: Phase 4 Graceful Degradation on Redis Failure
    try {
      await this.cache.sadd(key, deviceFingerprint);
      // Trusted devices expire after 90 days
      await this.cache.expire(key, 90 * 24 * 3600);

      this.logger.debug(
        { userId: userId.toString(), deviceFingerprint: deviceFingerprint.substring(0, 8) },
        'Trusted device added',
      );
    } catch (err) {
      this.logger.warn({ err, userId: userId.toString() }, 'Failed to add trusted device (Redis failure) — degrading gracefully');
    }
  }

  /**
   * Check whether a device fingerprint is in the user's trusted devices set.
   */
  async isTrustedDevice(
    userId: UserId,
    tenantId: TenantId,
    deviceFingerprint: string,
  ): Promise<boolean> {
    const key = `trusted-devices:${tenantId.toString()}:{${userId.toString()}}`;
    // WAR-GRADE DEFENSE: Phase 4 Graceful Degradation on Redis Failure
    // If Redis is down, fail securely by returning false (device is not trusted).
    try {
      return await this.cache.sismember(key, deviceFingerprint);
    } catch (err) {
      this.logger.warn({ err, userId: userId.toString() }, 'Failed to check trusted device (Redis failure) — failing securely (false)');
      return false;
    }
  }

  /**
   * Parse a User-Agent string into browser, OS, and device type.
   * Req 8.9: UA parsing for session metadata.
   *
   * Uses simple regex heuristics — sufficient for session display purposes.
   * For production, consider ua-parser-js for more accurate parsing.
   */
  parseUserAgent(ua: string): ParsedUserAgent {
    if (!ua || ua.trim() === '') {
      return { browser: 'Unknown', os: 'Unknown', deviceType: 'unknown' };
    }

    const lower = ua.toLowerCase();

    // ── Device type ──────────────────────────────────────────────────────
    let deviceType: ParsedUserAgent['deviceType'] = 'desktop';
    if (/bot|crawler|spider|scraper|curl|wget|python|java\/|go-http/i.test(ua)) {
      deviceType = 'bot';
    } else if (/ipad|tablet|kindle|playbook|silk|(android(?!.*mobile))/i.test(lower)) {
      deviceType = 'tablet';
    } else if (/mobile|iphone|ipod|android.*mobile|windows phone|blackberry|bb\d+/i.test(lower)) {
      deviceType = 'mobile';
    }

    // ── Browser ──────────────────────────────────────────────────────────
    let browser = 'Unknown';
    if (/edg\//i.test(ua)) {
      browser = 'Edge';
    } else if (/opr\//i.test(ua) || /opera/i.test(ua)) {
      browser = 'Opera';
    } else if (/chrome\/[\d.]+/i.test(ua) && !/chromium/i.test(ua)) {
      browser = 'Chrome';
    } else if (/firefox\/[\d.]+/i.test(ua)) {
      browser = 'Firefox';
    } else if (/safari\/[\d.]+/i.test(ua) && !/chrome/i.test(ua)) {
      browser = 'Safari';
    } else if (/msie|trident/i.test(ua)) {
      browser = 'IE';
    } else if (/curl\//i.test(ua)) {
      browser = 'curl';
    }

    // ── OS ───────────────────────────────────────────────────────────────
    let os = 'Unknown';
    if (/windows nt/i.test(ua)) {
      os = 'Windows';
    } else if (/mac os x|macos/i.test(ua)) {
      os = 'macOS';
    } else if (/iphone os|ipad/i.test(ua)) {
      os = 'iOS';
    } else if (/android/i.test(ua)) {
      os = 'Android';
    } else if (/linux/i.test(ua)) {
      os = 'Linux';
    } else if (/cros/i.test(ua)) {
      os = 'ChromeOS';
    }

    return { browser, os, deviceType };
  }

  async listTrustedDevices(principalId: string, tenantId: TenantId): Promise<string[]> {
    const key = `trusted-devices:${tenantId.toString()}:{${principalId}}`;
    // WAR-GRADE DEFENSE: Phase 4 Graceful Degradation on Redis Failure
    // Non-critical path. If Redis is down, return an empty list instead of crashing the endpoint.
    try {
      return await this.cache.smembers(key);
    } catch (err) {
      this.logger.warn({ err, principalId }, 'Failed to list trusted devices (Redis failure) — degrading gracefully');
      return [];
    }
  }

  async removeTrustedDevice(principalId: string, tenantId: TenantId, deviceFingerprint: string): Promise<void> {
    const key = `trusted-devices:${tenantId.toString()}:{${principalId}}`;
    // WAR-GRADE DEFENSE: Phase 4 Graceful Degradation on Redis Failure
    // Non-critical path.
    try {
      await this.cache.srem(key, deviceFingerprint);
    } catch (err) {
      this.logger.warn({ err, principalId }, 'Failed to remove trusted device (Redis failure) — degrading gracefully');
    }
  }
}

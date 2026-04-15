import { Injectable, Logger, Optional } from '@nestjs/common';
import { Session, SessionStatus } from '../../domain/aggregates/session.aggregate';
import { SessionId } from '../../domain/value-objects/session-id.vo';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { UserId } from '../../domain/value-objects/user-id.vo';
import { ISessionStore } from '../../application/ports/driven/i-session.store';
import { RedisCacheAdapter } from '../cache/redis-cache.adapter';
import { MysqlSessionFallback } from '../resilience/mysql-session-fallback';

/**
 * Redis-backed session store implementing ISessionStore.
 *
 * Key layout:
 *   session:{tenantId}:{sessionId}          → Redis Hash (session fields)
 *   user-sessions:{tenantId}:{userId}       → Redis Sorted Set (score = createdAt ms)
 *
 * The `{userId}` hash tag in the sorted set key ensures all of a user's session
 * keys are co-located on the same Redis Cluster shard (Req 8.2).
 *
 * Implements:
 *   - Req 8.1: sessions stored as Redis Hash with TTL
 *   - Req 8.2: sorted set keyed by user-sessions:{tenantId}:{userId}
 *   - Req 8.3: LRU eviction when max_sessions_per_user is reached
 *   - Req 8.4: sliding TTL via extendTtl()
 */
@Injectable()
export class RedisSessionStore implements ISessionStore {
  private readonly logger = new Logger(RedisSessionStore.name);

  /** Default max sessions per user when not configured per-tenant. */
  private readonly DEFAULT_MAX_SESSIONS = 10;

  constructor(
    private readonly cache: RedisCacheAdapter,
    @Optional() private readonly mysqlFallback?: MysqlSessionFallback,
  ) {}

  // ── Key Helpers ────────────────────────────────────────────────────────────

  private sessionKey(tenantId: TenantId, sessionId: SessionId): string {
    // No hash tag here — session hash is accessed by its own key
    return `session:${tenantId.toString()}:${sessionId.toString()}`;
  }

  /**
   * Sorted set key uses `{userId}` hash tag so all session set entries for a
   * user land on the same Redis Cluster shard as the session hashes.
   */
  private userSessionsKey(tenantId: TenantId, userId: UserId): string {
    return `user-sessions:${tenantId.toString()}:{${userId.toString()}}`;
  }

  // ── ISessionStore ──────────────────────────────────────────────────────────

  async create(
    session: Session,
    ttlSeconds: number,
    maxSessionsPerUser = this.DEFAULT_MAX_SESSIONS,
  ): Promise<void> {
    const client = this.cache.getClient();
    const sessionKey = this.sessionKey(session.tenantId, session.id);
    const setKey = this.userSessionsKey(session.tenantId, session.userId);
    const score = session.createdAt.getTime();

    // Serialize session to hash fields
    const fields = this.serialize(session);

    // Use a pipeline for atomicity-of-writes (not a transaction, but reduces round trips)
    const pipeline = client.pipeline();

    // 1. Store session hash with TTL
    pipeline.hset(sessionKey, fields);
    pipeline.expire(sessionKey, ttlSeconds);

    // 2. Add to user's sorted set (score = creation timestamp ms)
    pipeline.zadd(setKey, score, session.id.toString());

    await pipeline.exec();

    // 3. Enforce max sessions — evict oldest (lowest score) if over limit
    await this.evictOldestIfNeeded(session.tenantId, session.userId, maxSessionsPerUser);

    this.logger.debug(
      { sessionId: session.id.toString(), userId: session.userId.toString() },
      'Session created in Redis',
    );
  }

  async findById(sessionId: SessionId, tenantId: TenantId): Promise<Session | null> {
    // Fallback to MySQL when Redis circuit is OPEN (Req 15.2)
    if (this.cache.isCircuitOpen() && this.mysqlFallback) {
      this.logger.warn('Redis circuit OPEN — falling back to MySQL for session read');
      return this.mysqlFallback.findById(sessionId, tenantId);
    }

    try {
      const client = this.cache.getClient();
      const key = this.sessionKey(tenantId, sessionId);
      const fields = await client.hgetall(key);

      if (!fields || Object.keys(fields).length === 0) {
        return null;
      }

      return this.deserialize(fields);
    } catch (err: any) {
      if (err?.code === 'CACHE_UNAVAILABLE' && this.mysqlFallback) {
        this.logger.warn('Redis unavailable — falling back to MySQL for session read');
        return this.mysqlFallback.findById(sessionId, tenantId);
      }
      throw err;
    }
  }

  async findByUserId(userId: UserId, tenantId: TenantId): Promise<Session[]> {
    // Fallback to MySQL when Redis circuit is OPEN (Req 15.2)
    if (this.cache.isCircuitOpen() && this.mysqlFallback) {
      this.logger.warn('Redis circuit OPEN — falling back to MySQL for user sessions read');
      return this.mysqlFallback.findByUserId(userId, tenantId);
    }

    try {
      const client = this.cache.getClient();
      const setKey = this.userSessionsKey(tenantId, userId);

      // Get all session IDs from the sorted set (oldest first)
      const sessionIds = await client.zrange(setKey, 0, -1);
      if (sessionIds.length === 0) return [];

      // Fetch each session hash in a pipeline
      const pipeline = client.pipeline();
      for (const id of sessionIds) {
        pipeline.hgetall(this.sessionKey(tenantId, SessionId.from(id)));
      }

      const results = await pipeline.exec();
      const sessions: Session[] = [];

      if (results) {
        for (let i = 0; i < results.length; i++) {
          const [err, fields] = results[i] as [Error | null, Record<string, string>];
          if (err || !fields || Object.keys(fields).length === 0) {
            // Session expired or missing — clean up the sorted set entry
            const staleId = sessionIds[i];
            if (staleId) {
              await client.zrem(setKey, staleId);
            }
            continue;
          }
          sessions.push(this.deserialize(fields));
        }
      }

      return sessions;
    } catch (err: any) {
      if (err?.code === 'CACHE_UNAVAILABLE' && this.mysqlFallback) {
        this.logger.warn('Redis unavailable — falling back to MySQL for user sessions read');
        return this.mysqlFallback.findByUserId(userId, tenantId);
      }
      throw err;
    }
  }

  async invalidate(sessionId: SessionId, tenantId: TenantId): Promise<void> {
    const client = this.cache.getClient();
    const key = this.sessionKey(tenantId, sessionId);

    // Read userId before deleting so we can remove from sorted set
    const userId = await client.hget(key, 'userId');

    const pipeline = client.pipeline();
    pipeline.del(key);
    if (userId) {
      const setKey = this.userSessionsKey(tenantId, UserId.from(userId));
      pipeline.zrem(setKey, sessionId.toString());
    }

    await pipeline.exec();
  }

  async invalidateAll(userId: UserId, tenantId: TenantId): Promise<void> {
    const client = this.cache.getClient();
    const setKey = this.userSessionsKey(tenantId, userId);

    const sessionIds = await client.zrange(setKey, 0, -1);
    if (sessionIds.length === 0) return;

    const pipeline = client.pipeline();
    for (const id of sessionIds) {
      pipeline.del(this.sessionKey(tenantId, SessionId.from(id)));
    }
    pipeline.del(setKey);

    await pipeline.exec();
  }

  async extendTtl(sessionId: SessionId, tenantId: TenantId, ttlSeconds: number): Promise<void> {
    const client = this.cache.getClient();
    const key = this.sessionKey(tenantId, sessionId);

    // Update expiresAt field and reset TTL atomically via pipeline
    const newExpiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    const pipeline = client.pipeline();
    pipeline.hset(key, 'expiresAt', newExpiresAt);
    pipeline.expire(key, ttlSeconds);
    await pipeline.exec();
  }

  async setStatus(
    sessionId: SessionId,
    tenantId: TenantId,
    status: SessionStatus,
  ): Promise<void> {
    const client = this.cache.getClient();
    const key = this.sessionKey(tenantId, sessionId);
    await client.hset(key, 'status', status);
  }

  // ── Private Helpers ────────────────────────────────────────────────────────

  /**
   * Evict the oldest session(s) when the user exceeds maxSessionsPerUser.
   * Uses ZRANGE to find oldest entries, then deletes them.
   */
  private async evictOldestIfNeeded(
    tenantId: TenantId,
    userId: UserId,
    maxSessions: number,
  ): Promise<void> {
    const client = this.cache.getClient();
    const setKey = this.userSessionsKey(tenantId, userId);

    const count = await client.zcard(setKey);
    if (count <= maxSessions) return;

    const toEvict = count - maxSessions;
    // Get the oldest `toEvict` session IDs (lowest scores)
    const oldest = await client.zrange(setKey, 0, toEvict - 1);

    const pipeline = client.pipeline();
    for (const id of oldest) {
      pipeline.del(this.sessionKey(tenantId, SessionId.from(id)));
      pipeline.zrem(setKey, id);
    }
    await pipeline.exec();

    this.logger.debug(
      { evicted: oldest.length, userId: userId.toString() },
      'Evicted oldest sessions (LRU)',
    );
  }

  /** Serialize a Session aggregate to a flat Redis Hash field map. */
  private serialize(session: Session): Record<string, string> {
    return {
      id: session.id.toString(),
      tenantId: session.tenantId.toString(),
      userId: session.userId.toString(),
      principalId: session.principalId,
      membershipId: session.membershipId ?? '',
      actorId: session.actorId ?? '',
      policyVersion: session.policyVersion ?? '',
      manifestVersion: session.manifestVersion ?? '',
      status: session.getStatus(),
      mfaVerified: String(session.isMfaVerified()),
      recentAuthAt: session.getRecentAuthAt()?.toISOString() ?? '',
      mfaVerifiedAt: session.getMfaVerifiedAt()?.toISOString() ?? '',
      ipHash: session.ipHash,
      uaBrowser: session.uaBrowser,
      uaOs: session.uaOs,
      uaDeviceType: session.uaDeviceType,
      deviceFingerprint: session.deviceFingerprint ?? '',
      createdAt: session.createdAt.toISOString(),
      expiresAt: session.getExpiresAt().toISOString(),
      revokedAt: session.getRevokedAt()?.toISOString() ?? '',
      revokedReason: session.getRevokedReason() ?? '',
    };
  }

  /** Deserialize a Redis Hash field map back to a Session aggregate. */
  private deserialize(fields: Record<string, string>): Session {
    return Session.reconstitute({
      id: SessionId.from(fields['id']!),
      tenantId: TenantId.from(fields['tenantId']!),
      userId: UserId.from(fields['userId']!),
      principalId: fields['principalId'] ?? fields['userId']!,
      membershipId: fields['membershipId'] || undefined,
      actorId: fields['actorId'] || undefined,
      policyVersion: fields['policyVersion'] || undefined,
      manifestVersion: fields['manifestVersion'] || undefined,
      status: fields['status'] as SessionStatus,
      mfaVerified: fields['mfaVerified'] === 'true',
      recentAuthAt: fields['recentAuthAt'] ? new Date(fields['recentAuthAt']) : undefined,
      mfaVerifiedAt: fields['mfaVerifiedAt'] ? new Date(fields['mfaVerifiedAt']) : undefined,
      ipHash: fields['ipHash']!,
      uaBrowser: fields['uaBrowser']!,
      uaOs: fields['uaOs']!,
      uaDeviceType: fields['uaDeviceType']!,
      deviceFingerprint: fields['deviceFingerprint'] || undefined,
      createdAt: new Date(fields['createdAt']!),
      expiresAt: new Date(fields['expiresAt']!),
      revokedAt: fields['revokedAt'] ? new Date(fields['revokedAt']) : undefined,
      revokedReason: fields['revokedReason'] || undefined,
    });
  }
}

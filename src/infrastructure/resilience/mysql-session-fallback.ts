import { Injectable, Logger } from '@nestjs/common';
import { Inject } from '@nestjs/common';
import { Session, SessionStatus } from '../../domain/aggregates/session.aggregate';
import { SessionId } from '../../domain/value-objects/session-id.vo';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { UserId } from '../../domain/value-objects/user-id.vo';
import { ISessionStore } from '../../application/ports/driven/i-session.store';
import { MYSQL_POOL, DbPool } from '../db/mysql/mysql.module';

/**
 * MySQL-backed session store fallback (Req 15.2).
 *
 * Used when the Redis circuit breaker is OPEN.
 * Reads sessions from the `sessions` table in MySQL.
 *
 * Limitations vs Redis store:
 * - No sliding TTL (TTL managed by MySQL `expires_at` column)
 * - No sorted set for user session listing (uses table scan with index)
 * - Writes are not supported in fallback mode (session creation requires Redis)
 */
@Injectable()
export class MysqlSessionFallback implements ISessionStore {
  private readonly logger = new Logger(MysqlSessionFallback.name);

  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async create(session: Session, _ttlSeconds: number): Promise<void> {
    // In fallback mode, we cannot write to Redis.
    // Log a warning — the caller should handle this gracefully.
    this.logger.warn(
      { sessionId: session.id.toString() },
      'MysqlSessionFallback: create() called during Redis outage — session not persisted to Redis',
    );
    // Attempt to write to MySQL sessions table as best-effort
    try {
      await this.pool.execute(
        `INSERT INTO sessions
           (id, tenant_id, user_id, status, mfa_verified, ip_hash,
            ua_browser, ua_os, ua_device_type, device_fingerprint,
            created_at, expires_at)
         VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), UUID_TO_BIN(?), ?, ?, ?,
                 ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE status = VALUES(status)`,
        [
          session.id.toString(),
          session.tenantId.toString(),
          session.userId.toString(),
          session.getStatus(),
          session.isMfaVerified() ? 1 : 0,
          session.ipHash,
          session.uaBrowser,
          session.uaOs,
          session.uaDeviceType,
          session.deviceFingerprint ?? null,
          session.createdAt,
          session.getExpiresAt(),
        ],
      );
    } catch (err) {
      this.logger.error({ err }, 'MysqlSessionFallback: failed to write session to MySQL');
    }
  }

  async findById(sessionId: SessionId, tenantId: TenantId): Promise<Session | null> {
    this.logger.debug(
      { sessionId: sessionId.toString() },
      'MysqlSessionFallback: reading session from MySQL (Redis circuit open)',
    );

    const [rows] = await this.pool.execute<any[]>(
      `SELECT BIN_TO_UUID(id) AS id,
              BIN_TO_UUID(tenant_id) AS tenant_id,
              BIN_TO_UUID(user_id) AS user_id,
              status, mfa_verified, mfa_verified_at,
              ip_hash, ua_browser, ua_os, ua_device_type, device_fingerprint,
              created_at, expires_at, revoked_at, revoked_reason
         FROM sessions
        WHERE id = UUID_TO_BIN(?)
          AND tenant_id = UUID_TO_BIN(?)
          AND expires_at > NOW()
          AND status NOT IN ('EXPIRED', 'REVOKED')
        LIMIT 1`,
      [sessionId.toString(), tenantId.toString()],
    );

    if (!rows || rows.length === 0) return null;
    return this.rowToSession(rows[0]);
  }

  async findByUserId(userId: UserId, tenantId: TenantId): Promise<Session[]> {
    const [rows] = await this.pool.execute<any[]>(
      `SELECT BIN_TO_UUID(id) AS id,
              BIN_TO_UUID(tenant_id) AS tenant_id,
              BIN_TO_UUID(user_id) AS user_id,
              status, mfa_verified, mfa_verified_at,
              ip_hash, ua_browser, ua_os, ua_device_type, device_fingerprint,
              created_at, expires_at, revoked_at, revoked_reason
         FROM sessions
        WHERE user_id = UUID_TO_BIN(?)
          AND tenant_id = UUID_TO_BIN(?)
          AND expires_at > NOW()
          AND status NOT IN ('EXPIRED', 'REVOKED')
        ORDER BY created_at ASC`,
      [userId.toString(), tenantId.toString()],
    );

    return (rows ?? []).map((row: any) => this.rowToSession(row));
  }

  async invalidate(sessionId: SessionId, tenantId: TenantId): Promise<void> {
    await this.pool.execute(
      `UPDATE sessions
          SET status = 'REVOKED', revoked_at = NOW(), revoked_reason = 'LOGOUT'
        WHERE id = UUID_TO_BIN(?)
          AND tenant_id = UUID_TO_BIN(?)`,
      [sessionId.toString(), tenantId.toString()],
    );
  }

  async invalidateAll(userId: UserId, tenantId: TenantId): Promise<void> {
    await this.pool.execute(
      `UPDATE sessions
          SET status = 'REVOKED', revoked_at = NOW(), revoked_reason = 'LOGOUT_ALL'
        WHERE user_id = UUID_TO_BIN(?)
          AND tenant_id = UUID_TO_BIN(?)
          AND status NOT IN ('EXPIRED', 'REVOKED')`,
      [userId.toString(), tenantId.toString()],
    );
  }

  async extendTtl(sessionId: SessionId, tenantId: TenantId, ttlSeconds: number): Promise<void> {
    await this.pool.execute(
      `UPDATE sessions
          SET expires_at = DATE_ADD(NOW(), INTERVAL ? SECOND)
        WHERE id = UUID_TO_BIN(?)
          AND tenant_id = UUID_TO_BIN(?)`,
      [ttlSeconds, sessionId.toString(), tenantId.toString()],
    );
  }

  async setStatus(sessionId: SessionId, tenantId: TenantId, status: SessionStatus): Promise<void> {
    await this.pool.execute(
      `UPDATE sessions
          SET status = ?,
              mfa_verified = ?,
              mfa_verified_at = IF(? = 'ACTIVE', NOW(), mfa_verified_at)
        WHERE id = UUID_TO_BIN(?)
          AND tenant_id = UUID_TO_BIN(?)`,
      [
        status,
        status === 'ACTIVE' ? 1 : 0,
        status,
        sessionId.toString(),
        tenantId.toString(),
      ],
    );
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private rowToSession(row: any): Session {
    return Session.reconstitute({
      id: SessionId.from(row.id),
      tenantId: TenantId.from(row.tenant_id),
      userId: UserId.from(row.user_id),
      principalId: row.user_id,
      status: row.status as SessionStatus,
      mfaVerified: row.mfa_verified === 1,
      recentAuthAt: row.mfa_verified_at ? new Date(row.mfa_verified_at) : undefined,
      mfaVerifiedAt: row.mfa_verified_at ? new Date(row.mfa_verified_at) : undefined,
      ipHash: row.ip_hash,
      uaBrowser: row.ua_browser,
      uaOs: row.ua_os,
      uaDeviceType: row.ua_device_type,
      deviceFingerprint: row.device_fingerprint ?? undefined,
      createdAt: new Date(row.created_at),
      expiresAt: new Date(row.expires_at),
      revokedAt: row.revoked_at ? new Date(row.revoked_at) : undefined,
      revokedReason: row.revoked_reason ?? undefined,
    });
  }
}

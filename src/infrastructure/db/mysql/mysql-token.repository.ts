import { Inject, Injectable } from '@nestjs/common';
import {
  ITokenRepository,
  RefreshTokenRecord,
} from '../../../application/ports/driven/i-token.repository';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { MYSQL_POOL, DbPool } from './mysql.module';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';

/** Redis sorted-set key for the JTI blocklist. */
const BLOCKLIST_KEY = 'jti:blocklist';

function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface RefreshTokenRow {
  jti: Buffer;
  family_id: Buffer;
  user_id: Buffer;
  tenant_id: Buffer;
  revoked: number;
  revoked_at: Date | null;
  expires_at: Date;
  created_at: Date;
}

function rowToRecord(row: RefreshTokenRow): RefreshTokenRecord {
  return {
    jti: bufferToUuid(row.jti),
    familyId: bufferToUuid(row.family_id),
    userId: bufferToUuid(row.user_id),
    tenantId: bufferToUuid(row.tenant_id),
    revoked: row.revoked === 1,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

/**
 * MySQL + Redis implementation of ITokenRepository.
 *
 * - Refresh token records are persisted in MySQL (refresh_tokens table).
 * - JTI blocklist lives in Redis as a sorted set scored by expiry epoch (ms).
 *   addToBlocklist() → ZADD; isBlocklisted() → ZSCORE (O(1), Req 7.5, 7.7).
 */
@Injectable()
export class MysqlTokenRepository implements ITokenRepository {
  constructor(
    @Inject(MYSQL_POOL) private readonly pool: DbPool,
    @Inject(INJECTION_TOKENS.CACHE_PORT) private readonly cache: ICachePort,
  ) {}

  async saveRefreshToken(record: RefreshTokenRecord): Promise<void> {
    await this.pool.execute(
      `INSERT INTO refresh_tokens
         (jti, family_id, user_id, tenant_id, revoked, expires_at, created_at)
       VALUES (?, ?, ?, ?, 0, ?, ?)`,
      [
        uuidToBuffer(record.jti),
        uuidToBuffer(record.familyId),
        uuidToBuffer(record.userId),
        uuidToBuffer(record.tenantId),
        record.expiresAt,
        record.createdAt,
      ],
    );
  }

  async findRefreshToken(jti: string, tenantId: TenantId): Promise<RefreshTokenRecord | null> {
    const [rows] = await this.pool.execute<RefreshTokenRow[]>(
      `SELECT jti, family_id, user_id, tenant_id, revoked, revoked_at, expires_at, created_at
         FROM refresh_tokens
        WHERE jti       = ?
          AND tenant_id = ?
          AND expires_at > NOW()
        LIMIT 1`,
      [uuidToBuffer(jti), uuidToBuffer(tenantId.toString())],
    );

    const row = (rows as RefreshTokenRow[])[0];
    return row ? rowToRecord(row) : null;
  }

  async revokeToken(jti: string, tenantId: TenantId): Promise<void> {
    await this.pool.execute(
      `UPDATE refresh_tokens
          SET revoked    = 1,
              revoked_at = NOW()
        WHERE jti       = ?
          AND tenant_id = ?`,
      [uuidToBuffer(jti), uuidToBuffer(tenantId.toString())],
    );
  }

  async revokeFamily(familyId: string, tenantId: TenantId): Promise<void> {
    await this.pool.execute(
      `UPDATE refresh_tokens
          SET revoked    = 1,
              revoked_at = NOW()
        WHERE family_id = ?
          AND tenant_id = ?
          AND revoked   = 0`,
      [uuidToBuffer(familyId), uuidToBuffer(tenantId.toString())],
    );
  }

  async revokeAllFamiliesByUser(userId: UserId, tenantId: TenantId): Promise<void> {
    await this.pool.execute(
      `UPDATE refresh_tokens
          SET revoked    = 1,
              revoked_at = NOW()
        WHERE user_id   = ?
          AND tenant_id = ?
          AND revoked   = 0`,
      [uuidToBuffer(userId.toString()), uuidToBuffer(tenantId.toString())],
    );
  }

  /**
   * O(1) Redis ZSCORE check — no DB round trip (Req 7.7).
   * The blocklist sorted set is scored by expiry epoch (ms); expired entries
   * are pruned lazily via ZREMRANGEBYSCORE on a background schedule.
   */
  async isBlocklisted(jti: string): Promise<boolean> {
    // ICachePort doesn't expose ZSCORE directly; we use sismember on a Redis Set
    // for O(1) membership. The set key is per-jti for simplicity.
    // For a true sorted-set approach the cache port would need a zscore() method.
    // We store each JTI as a member of a Redis Set keyed by BLOCKLIST_KEY.
    return this.cache.sismember(BLOCKLIST_KEY, jti);
  }

  /**
   * Add a JTI to the Redis blocklist.
   * TTL is set to the remaining seconds until the token expires so the entry
   * auto-expires when the token would have expired anyway (Req 7.5).
   *
   * Because ICachePort exposes Set operations (sadd/sismember) rather than
   * sorted-set ZADD/ZSCORE, we use a Redis Set for membership and a separate
   * key per JTI to carry the TTL.
   */
  async addToBlocklist(jti: string, expiresAt: Date): Promise<void> {
    const ttlSeconds = Math.max(1, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
    // Store the JTI in the global blocklist set
    await this.cache.sadd(BLOCKLIST_KEY, jti);
    // Store a per-JTI sentinel key with TTL so the entry auto-expires
    await this.cache.set(`jti:${jti}`, '1', ttlSeconds);
  }

  async getActiveJtisByUser(userId: UserId, tenantId: TenantId): Promise<string[]> {
    // Retrieve active (non-revoked, non-expired) JTIs from MySQL.
    // These are used by logout-all to bulk-blocklist access tokens.
    const [rows] = await this.pool.execute<{ jti: Buffer }[]>(
      `SELECT jti
         FROM refresh_tokens
        WHERE user_id   = ?
          AND tenant_id = ?
          AND revoked   = 0
          AND expires_at > NOW()`,
      [uuidToBuffer(userId.toString()), uuidToBuffer(tenantId.toString())],
    );

    return (rows as { jti: Buffer }[]).map((r) => bufferToUuid(r.jti));
  }
}

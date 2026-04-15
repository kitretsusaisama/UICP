import { Injectable, Logger } from '@nestjs/common';
import { Inject } from '@nestjs/common';
import { ILockPort, LockOptions, LockToken } from '../../application/ports/driven/i-lock.port';
import { MYSQL_POOL, DbPool } from '../db/mysql/mysql.module';

/**
 * MySQL advisory lock fallback implementing ILockPort (Req 15.2, 15.6).
 *
 * Used when the Redis circuit breaker is OPEN and distributed locking
 * via Redis is unavailable.
 *
 * Uses MySQL `GET_LOCK(name, timeout)` / `RELEASE_LOCK(name)` advisory locks.
 *
 * Properties:
 * - At most one process holds a given lock key at any point in time (Req 15.6)
 *   because MySQL advisory locks are server-scoped and mutually exclusive.
 * - Locks are automatically released when the connection is closed.
 * - Lock names are scoped to 64 characters (MySQL limit).
 *
 * Limitations vs Redis lock:
 * - Tied to a single MySQL connection (not connection-pool safe for the same key)
 * - No TTL-based auto-expiry (relies on connection lifecycle)
 * - Lower throughput than Redis SET NX
 */
@Injectable()
export class MysqlAdvisoryLock implements ILockPort {
  private readonly logger = new Logger(MysqlAdvisoryLock.name);

  /** MySQL advisory lock name max length. */
  private readonly MAX_LOCK_NAME_LENGTH = 64;

  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  /**
   * Acquire a MySQL advisory lock.
   *
   * Uses `SELECT GET_LOCK(name, timeoutSeconds)`.
   * Returns 1 on success, 0 on timeout, NULL on error.
   *
   * @throws Error with code LOCK_CONFLICT when lock cannot be acquired.
   */
  async acquire(key: string, ttlMs: number, options?: LockOptions): Promise<LockToken> {
    const lockName = this.sanitizeLockName(key);
    const timeoutSeconds = Math.ceil(ttlMs / 1000);
    const maxRetries = options?.maxRetries ?? 3;
    const baseDelay = options?.retryDelayMs ?? 200;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const conn = await this.pool.getConnection();
      try {
        const [rows] = await conn.execute<any[]>(
          `SELECT GET_LOCK(?, ?) AS acquired`,
          [lockName, timeoutSeconds],
        );

        const acquired = rows?.[0]?.acquired;

        if (acquired === 1) {
          this.logger.debug({ key: lockName, attempt }, 'MySQL advisory lock acquired');
          // Store connection reference in token value for release
          // We use the lock name as the value since MySQL tracks by connection
          return {
            key: lockName,
            value: lockName,
            acquiredAt: new Date(),
            ttlMs,
          };
        }

        // Release connection back to pool before retry
        conn.release();

        if (attempt < maxRetries) {
          const delay = this.backoffWithJitter(baseDelay, attempt);
          this.logger.debug({ key: lockName, attempt, delay }, 'MySQL advisory lock contention — retrying');
          await this.sleep(delay);
        }
      } catch (err) {
        conn.release();
        throw err;
      }
    }

    this.logger.warn({ key: lockName, maxRetries }, 'Failed to acquire MySQL advisory lock');
    throw Object.assign(
      new Error(`LOCK_CONFLICT: Could not acquire MySQL advisory lock on key "${key}" after ${maxRetries} retries`),
      { code: 'LOCK_CONFLICT' },
    );
  }

  /**
   * Release a MySQL advisory lock.
   *
   * Uses `SELECT RELEASE_LOCK(name)`.
   * Returns 1 on success, 0 if not held by this connection, NULL if not exists.
   */
  async release(token: LockToken): Promise<void> {
    const conn = await this.pool.getConnection();
    try {
      const [rows] = await conn.execute<any[]>(
        `SELECT RELEASE_LOCK(?) AS released`,
        [token.key],
      );

      const released = rows?.[0]?.released;
      if (released !== 1) {
        this.logger.warn(
          { key: token.key, released },
          'MySQL advisory lock release: not held by this connection or already released',
        );
      } else {
        this.logger.debug({ key: token.key }, 'MySQL advisory lock released');
      }
    } finally {
      conn.release();
    }
  }

  /**
   * Extend a MySQL advisory lock TTL.
   *
   * MySQL advisory locks do not support TTL extension natively.
   * This is a no-op — the lock remains held until explicitly released
   * or the connection closes.
   */
  async extend(_token: LockToken, _additionalMs: number): Promise<void> {
    // MySQL advisory locks don't have TTL — they're held until released or connection closes.
    // This is acceptable for the fallback scenario.
    this.logger.debug('MysqlAdvisoryLock.extend() is a no-op — MySQL advisory locks have no TTL');
  }

  // ── Private ────────────────────────────────────────────────────────────────

  /**
   * Sanitize lock name to MySQL's 64-character limit.
   * Uses a hash suffix if the name exceeds the limit.
   */
  private sanitizeLockName(key: string): string {
    if (key.length <= this.MAX_LOCK_NAME_LENGTH) {
      return key;
    }
    // Truncate and append a short hash to maintain uniqueness
    const { createHash } = require('crypto') as typeof import('crypto');
    const hash = createHash('sha256').update(key).digest('hex').substring(0, 8);
    return `${key.substring(0, this.MAX_LOCK_NAME_LENGTH - 9)}_${hash}`;
  }

  private backoffWithJitter(baseMs: number, attempt: number): number {
    const cap = 5_000;
    const exponential = Math.min(cap, baseMs * Math.pow(2, attempt));
    return Math.floor(Math.random() * exponential);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

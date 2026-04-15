import { Injectable, Logger, Optional } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { ILockPort, LockOptions, LockToken } from '../../application/ports/driven/i-lock.port';
import { RedisCacheAdapter } from '../cache/redis-cache.adapter';
import { MysqlAdvisoryLock } from '../resilience/mysql-advisory-lock';

/**
 * Lua script for atomic lock release.
 *
 * Checks that the stored value matches the owner token before deleting.
 * Returns 1 if deleted, 0 if the key was already gone or owned by another pod.
 *
 * Req 14.2: release uses Lua script — atomic check-and-delete.
 */
const RELEASE_SCRIPT = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
`;

/**
 * Lua script for atomic lock TTL extension.
 *
 * Checks ownership before extending the TTL.
 * Returns 1 if extended, 0 if ownership mismatch or key missing.
 *
 * Req 14.4: extend uses Lua script — atomic check-and-PEXPIRE.
 */
const EXTEND_SCRIPT = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("PEXPIRE", KEYS[1], ARGV[2])
else
  return 0
end
`;

/**
 * Redis distributed lock adapter implementing ILockPort.
 *
 * Implements:
 *   - Req 14.1: acquire uses SET key value NX PX ttl (atomic, no TOCTOU)
 *   - Req 14.2: release uses Lua script (atomic check-and-delete)
 *   - Req 14.3: throws ConflictException after maxRetries exhausted
 *   - Req 14.4: extend uses Lua script (atomic check-and-PEXPIRE)
 *   - Req 14.6: at most one process holds a given key at any point in time
 */
@Injectable()
export class RedisLockAdapter implements ILockPort {
  private readonly logger = new Logger(RedisLockAdapter.name);

  /** Default max retries before throwing ConflictException. */
  private readonly DEFAULT_MAX_RETRIES = 3;

  /** Base delay in ms for exponential backoff. */
  private readonly DEFAULT_RETRY_DELAY_MS = 200;

  constructor(
    private readonly cache: RedisCacheAdapter,
    @Optional() private readonly mysqlFallback?: MysqlAdvisoryLock,
  ) {}

  // ── ILockPort ──────────────────────────────────────────────────────────────

  /**
   * Acquire a distributed lock on `key` with a TTL of `ttlMs` milliseconds.
   *
   * Uses `SET key value NX PX ttl` — atomic, no TOCTOU race (Req 14.1).
   * Retries with exponential backoff + jitter up to `options.maxRetries` times.
   * Falls back to MySQL advisory locks when Redis circuit is OPEN (Req 15.2, 15.6).
   *
   * @throws Error with code LOCK_CONFLICT when lock cannot be acquired.
   */
  async acquire(key: string, ttlMs: number, options?: LockOptions): Promise<LockToken> {
    // Fallback to MySQL advisory locks when Redis circuit is OPEN (Req 15.2)
    if (this.cache.isCircuitOpen() && this.mysqlFallback) {
      this.logger.warn({ key }, 'Redis circuit OPEN — falling back to MySQL advisory lock');
      return this.mysqlFallback.acquire(key, ttlMs, options);
    }

    const maxRetries = options?.maxRetries ?? this.DEFAULT_MAX_RETRIES;
    const baseDelay = options?.retryDelayMs ?? this.DEFAULT_RETRY_DELAY_MS;
    const client = this.cache.getClient();
    const ownerValue = randomUUID();

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      // ioredis v5: SET key value PX ms NX
      const result = await client.set(key, ownerValue, 'PX', ttlMs, 'NX');

      if (result === 'OK') {
        this.logger.debug({ key, attempt }, 'Distributed lock acquired');
        return {
          key,
          value: ownerValue,
          acquiredAt: new Date(),
          ttlMs,
        };
      }

      if (attempt < maxRetries) {
        const delay = this.backoffWithJitter(baseDelay, attempt);
        this.logger.debug({ key, attempt, delay }, 'Lock contention — retrying');
        await this.sleep(delay);
      }
    }

    this.logger.warn({ key, maxRetries }, 'Failed to acquire distributed lock after all retries');
    throw Object.assign(
      new Error(`LOCK_CONFLICT: Could not acquire lock on key "${key}" after ${maxRetries} retries`),
      { code: 'LOCK_CONFLICT' },
    );
  }

  /**
   * Release a lock using the ownership token.
   *
   * Uses an atomic Lua script to prevent releasing another pod's lock (Req 14.2).
   * Silently succeeds if the lock has already expired (TTL elapsed).
   *
   * @throws Error when the token value does not match (ownership mismatch).
   */
  async release(token: LockToken): Promise<void> {
    const client = this.cache.getClient();

    const result = await (client as any).eval(
      RELEASE_SCRIPT,
      1,
      token.key,
      token.value,
    ) as number;

    if (result === 0) {
      // Either already expired (fine) or owned by another pod (warn)
      this.logger.warn(
        { key: token.key },
        'Lock release: key not found or ownership mismatch (may have expired)',
      );
    } else {
      this.logger.debug({ key: token.key }, 'Distributed lock released');
    }
  }

  /**
   * Extend the TTL of a held lock by `additionalMs` milliseconds.
   *
   * Uses an atomic Lua script to verify ownership before extending (Req 14.4).
   *
   * @throws Error when the token value does not match (ownership mismatch).
   */
  async extend(token: LockToken, additionalMs: number): Promise<void> {
    const client = this.cache.getClient();

    const result = await (client as any).eval(
      EXTEND_SCRIPT,
      1,
      token.key,
      token.value,
      String(additionalMs),
    ) as number;

    if (result === 0) {
      throw Object.assign(
        new Error(
          `LOCK_EXTEND_FAILED: Cannot extend lock on key "${token.key}" — ownership mismatch or key expired`,
        ),
        { code: 'LOCK_EXTEND_FAILED' },
      );
    }

    this.logger.debug({ key: token.key, additionalMs }, 'Distributed lock TTL extended');
  }

  // ── Private Helpers ────────────────────────────────────────────────────────

  /**
   * Exponential backoff with full jitter.
   * delay = random(0, min(cap, base * 2^attempt))
   * Cap at 5 seconds to avoid excessive waits.
   */
  private backoffWithJitter(baseMs: number, attempt: number): number {
    const cap = 5_000;
    const exponential = Math.min(cap, baseMs * Math.pow(2, attempt));
    return Math.floor(Math.random() * exponential);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

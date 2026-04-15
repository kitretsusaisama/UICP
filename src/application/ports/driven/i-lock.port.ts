/**
 * Options for lock acquisition.
 */
export interface LockOptions {
  /** Maximum number of acquisition retries. Default: 3. */
  maxRetries?: number;
  /** Base retry delay in milliseconds (exponential backoff + jitter). Default: 200. */
  retryDelayMs?: number;
}

/**
 * Opaque lock ownership token returned by `acquire`.
 * Must be passed to `release` and `extend` to prove ownership.
 */
export interface LockToken {
  /** The Redis key that is locked. */
  key: string;
  /** Random UUID — proves ownership (prevents releasing another pod's lock). */
  value: string;
  acquiredAt: Date;
  ttlMs: number;
}

/**
 * Driven port — Redis distributed locking (Section 4.7, Req 14).
 *
 * Contract:
 * - `acquire` uses `SET key value NX PX ttl` — atomic, no TOCTOU race (Req 14.1).
 * - `release` uses a Lua script: GET + compare + DEL in one round trip (Req 14.2).
 * - `extend` uses a Lua script: GET + compare + PEXPIRE in one round trip (Req 14.4).
 * - At most one process holds a given key at any point in time (Req 14.6, Property 15).
 * - Throws `ConflictException` when lock cannot be acquired after `maxRetries` (Req 14.3).
 */
export interface ILockPort {
  /**
   * Acquire a distributed lock on `key` with a TTL of `ttlMs` milliseconds.
   * Retries with exponential backoff + jitter up to `options.maxRetries` times.
   *
   * @throws `ConflictException` when the lock cannot be acquired after all retries.
   */
  acquire(key: string, ttlMs: number, options?: LockOptions): Promise<LockToken>;

  /**
   * Release a lock using the ownership token.
   * Uses an atomic Lua script to prevent releasing another pod's lock.
   *
   * @throws when `token.value` does not match the stored value (ownership mismatch).
   */
  release(token: LockToken): Promise<void>;

  /**
   * Extend the TTL of a held lock by `additionalMs` milliseconds.
   * Uses an atomic Lua script to verify ownership before extending.
   *
   * @throws when `token.value` does not match the stored value (ownership mismatch).
   */
  extend(token: LockToken, additionalMs: number): Promise<void>;
}

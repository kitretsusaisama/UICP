import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { ClsService } from 'nestjs-cls';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { ILockPort, LockOptions, LockToken } from '../ports/driven/i-lock.port';

/**
 * Application service — distributed lock helper.
 *
 * Wraps ILockPort with:
 *   - Retry budget tracking via CLS context (prevents retry storms)
 *   - `withLock(key, ttl, fn)` convenience helper for RAII-style locking
 *   - MySQL advisory lock fallback when Redis circuit breaker is OPEN (Req 15.2)
 *
 * Implements:
 *   - Req 14.1–14.6: distributed locking for signup, session creation, token rotation
 *   - Req 15.2: retry budget prevents cascading lock retries; MySQL fallback when Redis is OPEN
 */
@Injectable()
export class DistributedLockService {
  private readonly logger = new Logger(DistributedLockService.name);

  /** Default per-request retry budget (total lock retries across all locks). */
  private readonly DEFAULT_RETRY_BUDGET = 3;

  constructor(
    @Inject(INJECTION_TOKENS.LOCK_PORT)
    private readonly lockPort: ILockPort,
    private readonly cls: ClsService,
    /**
     * Optional MySQL advisory lock fallback (Req 15.2).
     * Injected by the infrastructure module when available.
     * When the Redis circuit breaker is OPEN, this fallback is used instead.
     */
    @Optional() @Inject('MYSQL_ADVISORY_LOCK_FALLBACK')
    private readonly mysqlFallback?: ILockPort,
    /**
     * Optional circuit breaker state checker.
     * Injected as a function so the service has no direct dependency on Redis infrastructure.
     */
    @Optional() @Inject('REDIS_CIRCUIT_OPEN_FN')
    private readonly isRedisCircuitOpen?: () => boolean,
  ) {}

  /**
   * Acquire a lock, execute `fn`, then release the lock — even on exception.
   *
   * Tracks retry budget in CLS context to prevent retry storms across
   * multiple lock acquisitions within the same request (Req 15.2).
   *
   * Falls back to MySQL advisory locks when Redis circuit breaker is OPEN (Req 15.2).
   *
   * @param key   Redis key to lock on
   * @param ttlMs Lock TTL in milliseconds
   * @param fn    Async function to execute while holding the lock
   * @param opts  Optional lock acquisition options
   */
  async withLock<T>(
    key: string,
    ttlMs: number,
    fn: () => Promise<T>,
    opts?: LockOptions,
  ): Promise<T> {
    const budget = this.consumeRetryBudget();
    const effectiveOpts: LockOptions = {
      maxRetries: Math.min(opts?.maxRetries ?? 3, budget),
      retryDelayMs: opts?.retryDelayMs ?? 200,
    };

    // Req 15.2: fall back to MySQL advisory locks when Redis circuit is OPEN
    const port = this.resolvePort();

    let token: LockToken | undefined;
    try {
      token = await port.acquire(key, ttlMs, effectiveOpts);
      this.logger.debug({ key }, 'Lock acquired');

      return await fn();
    } finally {
      if (token) {
        try {
          await port.release(token);
          this.logger.debug({ key }, 'Lock released');
        } catch (releaseErr) {
          // Log but don't rethrow — the lock will expire via TTL
          this.logger.warn({ key, err: releaseErr }, 'Lock release failed (will expire via TTL)');
        }
      }
    }
  }

  /**
   * Acquire a lock and return the token.
   * Caller is responsible for calling `release(token)`.
   *
   * Falls back to MySQL advisory locks when Redis circuit breaker is OPEN (Req 15.2).
   */
  async acquire(key: string, ttlMs: number, opts?: LockOptions): Promise<LockToken> {
    const budget = this.consumeRetryBudget();
    const effectiveOpts: LockOptions = {
      maxRetries: Math.min(opts?.maxRetries ?? 3, budget),
      retryDelayMs: opts?.retryDelayMs ?? 200,
    };
    return this.resolvePort().acquire(key, ttlMs, effectiveOpts);
  }

  /**
   * Release a previously acquired lock token.
   */
  async release(token: LockToken): Promise<void> {
    return this.resolvePort().release(token);
  }

  /**
   * Extend the TTL of a held lock.
   */
  async extend(token: LockToken, additionalMs: number): Promise<void> {
    return this.resolvePort().extend(token, additionalMs);
  }

  // ── Lock key helpers ───────────────────────────────────────────────────────

  /** Lock key for signup identity creation (Req 14.5). */
  static identityLockKey(tenantId: string, identityHash: string): string {
    return `lock:identity:${tenantId}:${identityHash}`;
  }

  /** Lock key for session creation per user (Req 14.5). */
  static sessionCreationLockKey(tenantId: string, userId: string): string {
    return `lock:session-create:${tenantId}:${userId}`;
  }

  /** Lock key for refresh token family rotation (Req 14.5). */
  static tokenFamilyLockKey(familyId: string): string {
    return `lock:token-family:${familyId}`;
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  /**
   * Resolve which lock port to use.
   *
   * When the Redis circuit breaker is OPEN and a MySQL fallback is available,
   * returns the MySQL advisory lock port (Req 15.2).
   * Otherwise returns the primary Redis lock port.
   */
  private resolvePort(): ILockPort {
    if (
      this.mysqlFallback &&
      this.isRedisCircuitOpen &&
      this.isRedisCircuitOpen()
    ) {
      this.logger.warn('Redis circuit OPEN — using MySQL advisory lock fallback');
      return this.mysqlFallback;
    }
    return this.lockPort;
  }

  /**
   * Consume one unit from the per-request retry budget stored in CLS.
   * Returns the remaining budget (minimum 0).
   *
   * If no CLS context is active (e.g., background workers), returns the default budget.
   */
  private consumeRetryBudget(): number {
    try {
      const current = (this.cls.get('lockRetryBudget') as number | undefined) ?? this.DEFAULT_RETRY_BUDGET;
      const remaining = Math.max(0, current - 1);
      this.cls.set('lockRetryBudget' as any, remaining);
      return remaining;
    } catch {
      // CLS not active (background job context)
      return this.DEFAULT_RETRY_BUDGET;
    }
  }
}

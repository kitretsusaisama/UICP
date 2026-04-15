import { Inject, Injectable, Logger } from '@nestjs/common';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { ICachePort } from '../ports/driven/i-cache.port';

/** Cached idempotency response envelope. */
export interface IdempotencyRecord {
  statusCode: number;
  body: unknown;
  headers?: Record<string, string>;
  createdAt: string;
}

/**
 * Application service — idempotency key management.
 *
 * Implements:
 *   - Req 2.8: cache response for 24h; return cached response on replay
 *   - Property 14: two requests with the same idempotency key return identical responses
 *
 * Key format: idempotency:{tenantId}:{idempotencyKey}
 * TTL: 86400 seconds (24 hours)
 */
@Injectable()
export class IdempotencyService {
  private readonly logger = new Logger(IdempotencyService.name);

  /** 24-hour TTL for cached responses (Req 2.8). */
  private readonly TTL_S = 86_400;

  constructor(
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {}

  /**
   * Check whether a cached response exists for the given idempotency key.
   * Returns the cached record when found, null otherwise.
   *
   * Req 2.8: return cached response for subsequent requests with the same key.
   */
  async check(tenantId: string, idempotencyKey: string): Promise<IdempotencyRecord | null> {
    const key = this.cacheKey(tenantId, idempotencyKey);
    const raw = await this.cache.get(key);

    if (raw === null) return null;

    try {
      return JSON.parse(raw) as IdempotencyRecord;
    } catch {
      this.logger.warn({ key }, 'Failed to parse cached idempotency record — treating as miss');
      return null;
    }
  }

  /**
   * Store a response under the given idempotency key with a 24h TTL.
   *
   * Req 2.8: cache the response for 24 hours.
   */
  async store(
    tenantId: string,
    idempotencyKey: string,
    record: Omit<IdempotencyRecord, 'createdAt'>,
  ): Promise<void> {
    const key = this.cacheKey(tenantId, idempotencyKey);
    const full: IdempotencyRecord = {
      ...record,
      createdAt: new Date().toISOString(),
    };

    await this.cache.set(key, JSON.stringify(full), this.TTL_S);

    this.logger.debug({ key }, 'Idempotency response cached');
  }

  /**
   * Convenience helper — returns true when a cached response exists.
   * Used by the IdempotencyInterceptor to short-circuit request processing.
   */
  async isReplay(tenantId: string, idempotencyKey: string): Promise<boolean> {
    const record = await this.check(tenantId, idempotencyKey);
    return record !== null;
  }

  private cacheKey(tenantId: string, idempotencyKey: string): string {
    return `idempotency:${tenantId}:${idempotencyKey}`;
  }
}

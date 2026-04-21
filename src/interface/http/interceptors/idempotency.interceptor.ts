import {
  CallHandler,
  ExecutionContext,
  Inject,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { Observable, tap } from 'rxjs';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';

const IDEMPOTENCY_TTL_S = 86_400; // 24 hours

interface CachedResponse {
  statusCode: number;
  body: unknown;
  createdAt: string;
}

/**
 * IdempotencyInterceptor — prevents duplicate processing of retried requests.
 *
 * Implements: Req 2.8
 *
 * Behaviour:
 *  1. Reads `X-Idempotency-Key` header — skips if absent.
 *  2. Checks Redis cache via ICachePort using key `idempotency:{tenantId}:{key}`.
 *  3. On cache hit: returns cached response with `x-idempotency-replayed: true`.
 *  4. On cache miss: stores response after handler completes.
 */
@Injectable()
export class IdempotencyInterceptor implements NestInterceptor {
  private readonly logger = new Logger(IdempotencyInterceptor.name);

  constructor(
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {}

  async intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Promise<Observable<unknown>> {
    const req = context.switchToHttp().getRequest<Record<string, unknown> & { headers: Record<string, string | string[] | undefined> }>();
    const res = context.switchToHttp().getResponse<{ statusCode: number; status(code: number): void; setHeader(name: string, value: string): void }>();

    const idempotencyKey = req.headers['x-idempotency-key'] as string | undefined;
    if (!idempotencyKey) {
      return next.handle();
    }

    const tenantId = (req['tenantId'] as string | undefined) ?? 'global';
    const cacheKey = `idempotency:${tenantId}:${idempotencyKey}`;

    // Check for cached response or acquire lock
    // WAR-GRADE DEFENSE: Phase 11 Temporal Consistency Control
    // Replaced naive cache check with atomic SET NX to prevent concurrent request replay races
    try {
      // 1. Try to set the key with a "PENDING" status atomically.
      // If it fails (returns false/null), the key already exists (either PENDING or COMPLETED).
      const pendingRecord: CachedResponse = {
        statusCode: 202, // Accepted/Processing
        body: { error: 'Request is currently processing' },
        createdAt: new Date().toISOString(),
        meta: {
          idempotencyState: 'PENDING',
        },
      };

      const client = (this.cache as any).getClient?.();
      let acquired = false;
      if (client && typeof client.set === 'function') {
        const result = await client.set(cacheKey, JSON.stringify(pendingRecord), 'EX', IDEMPOTENCY_TTL_S, 'NX');
        acquired = result === 'OK';
      } else {
        // Fallback for non-redis caches
        const existing = await this.cache.get(cacheKey);
        if (!existing) {
          await this.cache.set(cacheKey, JSON.stringify(pendingRecord), IDEMPOTENCY_TTL_S);
          acquired = true;
        }
      }

      if (!acquired) {
        // Key exists. Fetch it.
        const cached = await this.cache.get(cacheKey);
        if (cached !== null) {
          const record = JSON.parse(cached) as CachedResponse;

          if (record.meta?.idempotencyState === 'PENDING') {
            // Concurrent request is currently executing
            res.status(409); // Conflict
            return new Observable((subscriber) => {
              subscriber.next({
                error: {
                  code: 'CONCURRENT_REQUEST',
                  message: 'A request with this idempotency key is currently processing',
                }
              });
              subscriber.complete();
            });
          }

          // Completed cached response
          res.status(record.statusCode);
          res.setHeader('x-idempotency-replayed', 'true');
          this.logger.debug({ cacheKey }, 'Idempotency cache hit — replaying response');
          return new Observable((subscriber) => {
            subscriber.next(record.body);
            subscriber.complete();
          });
        }
      }
    } catch (err) {
      this.logger.warn({ cacheKey, err }, 'Idempotency cache lock failed — proceeding normally (fail open)');
    }

    // Cache acquired (we hold the PENDING lock) — execute handler and store final response
    return next.handle().pipe(
      tap({
        next: async (body) => {
          try {
            const record: CachedResponse = {
              statusCode: res.statusCode,
              body,
              createdAt: new Date().toISOString(),
            };
            // Overwrite the PENDING state with the actual response
            await this.cache.set(cacheKey, JSON.stringify(record), IDEMPOTENCY_TTL_S);
            this.logger.debug({ cacheKey }, 'Idempotency response cached');
          } catch (err) {
            this.logger.warn({ cacheKey, err }, 'Idempotency cache write failed');
          }
        },
        error: async (err) => {
          try {
            // If the handler throws an error, we should delete the idempotency key
            // so the client can safely retry the failed request.
            await this.cache.del(cacheKey);
            this.logger.debug({ cacheKey }, 'Idempotency lock released due to handler error');
          } catch (delErr) {
            this.logger.warn({ cacheKey, delErr }, 'Failed to release idempotency lock after handler error');
          }
        }
      }),
    );
  }
}

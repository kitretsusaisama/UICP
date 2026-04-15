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

    // Check for cached response
    try {
      const cached = await this.cache.get(cacheKey);
      if (cached !== null) {
        const record = JSON.parse(cached) as CachedResponse;
        res.status(record.statusCode);
        res.setHeader('x-idempotency-replayed', 'true');
        this.logger.debug({ cacheKey }, 'Idempotency cache hit — replaying response');
        return new Observable((subscriber) => {
          subscriber.next(record.body);
          subscriber.complete();
        });
      }
    } catch (err) {
      this.logger.warn({ cacheKey, err }, 'Idempotency cache read failed — proceeding normally');
    }

    // Cache miss — execute handler and store response
    return next.handle().pipe(
      tap({
        next: async (body) => {
          try {
            const record: CachedResponse = {
              statusCode: res.statusCode,
              body,
              createdAt: new Date().toISOString(),
            };
            await this.cache.set(cacheKey, JSON.stringify(record), IDEMPOTENCY_TTL_S);
            this.logger.debug({ cacheKey }, 'Idempotency response cached');
          } catch (err) {
            this.logger.warn({ cacheKey, err }, 'Idempotency cache write failed');
          }
        },
      }),
    );
  }
}

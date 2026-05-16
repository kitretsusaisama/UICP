/**
 * Cache Interceptor
 *
 * Intercepts GET requests and serves cached responses from Redis when available.
 * Cache keys: cache:{tenant}:{method}:{path}:{hash(params)}
 */

import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable, of } from 'rxjs';
import { ClsService } from 'nestjs-cls';
import { ResponseCacheService } from '../../../application/services/cache/response-cache.service';

interface HttpRequest {
  method: string;
  path: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, unknown>;
}

@Injectable()
export class CacheInterceptor implements NestInterceptor {
  constructor(
    private readonly cls: ClsService,
    private readonly cacheService: ResponseCacheService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<HttpRequest>();
    const method = request.method;
    const path = request.path || request.url;
    const query = request.query || {};

    // Only cache GET requests
    if (!this.cacheService.shouldCache(method, path)) {
      return next.handle();
    }

    // Get tenant ID from headers or CLS
    const tenantIdHeader = request.headers['x-tenant-id'];
    const tenantId = Array.isArray(tenantIdHeader) ? tenantIdHeader[0] : tenantIdHeader ?? this.cls.get('tenantId') as string | undefined;
    const cacheKey = this.cacheService.generateKey(tenantId, method, path, query);

    if (!cacheKey) {
      return next.handle();
    }

    return next.handle();
  }
}

/**
 * Async cache interceptor that properly handles Redis lookups.
 * Use this when you need full async cache checking.
 */
@Injectable()
export class AsyncCacheInterceptor implements NestInterceptor {
  constructor(
    private readonly cls: ClsService,
    private readonly cacheService: ResponseCacheService,
  ) {}

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<unknown>> {
    const request = context.switchToHttp().getRequest<HttpRequest>();
    const method = request.method;
    const path = request.path || request.url;
    const query = request.query || {};

    if (!this.cacheService.shouldCache(method, path)) {
      return next.handle();
    }

    const tenantIdHeader = request.headers['x-tenant-id'];
    const tenantId = Array.isArray(tenantIdHeader) ? tenantIdHeader[0] : tenantIdHeader ?? this.cls.get('tenantId') as string | undefined;
    const cacheKey = this.cacheService.generateKey(tenantId, method, path, query);

    if (!cacheKey) {
      return next.handle();
    }

    const cached = await this.cacheService.get(cacheKey);
    if (cached) {
      return of(cached.data);
    }

    return next.handle();
  }
}
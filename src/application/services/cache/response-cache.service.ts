/**
 * Response Cache Service
 *
 * Provides Redis-based HTTP response caching with configurable TTL.
 * Cache keys: cache:{tenant}:{method}:{hash(params)}
 */

import { Inject, Injectable, Logger } from '@nestjs/common';
import { ICachePort } from '../../ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import * as crypto from 'crypto';

export interface CacheConfig {
  /** Default TTL in seconds */
  defaultTtlSeconds: number;
  /** Cache key prefix */
  prefix: string;
  /** Methods to cache (GET only by default) */
  methods: string[];
}

export interface CachedResponse<T = unknown> {
  data: T;
  cachedAt: number;
  ttl: number;
}

/**
 * ResponseCacheService — manages HTTP response caching in Redis.
 */
@Injectable()
export class ResponseCacheService {
  private readonly logger = new Logger(ResponseCacheService.name);
  private readonly config: CacheConfig = {
    defaultTtlSeconds: 300, // 5 minutes
    prefix: 'cache',
    methods: ['GET'],
  };

  constructor(
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {}

  /**
   * Generate a cache key from request details.
   */
  generateKey(
    tenantId: string | undefined,
    method: string,
    path: string,
    queryParams: Record<string, unknown> = {},
  ): string {
    // Skip caching for non-cacheable methods
    if (!this.config.methods.includes(method.toUpperCase())) {
      return '';
    }

    const paramsHash = this.hashParams(queryParams);
    const cleanPath = path.replace(/\/+$/, ''); // Remove trailing slashes

    return `${this.config.prefix}:${tenantId || 'global'}:${method}:${cleanPath}:${paramsHash}`;
  }

  /**
   * Get cached response if available and not expired.
   */
  async get<T>(key: string): Promise<CachedResponse<T> | null> {
    if (!key) return null;

    try {
      const stored = await this.cache.get(key);
      if (!stored) return null;

      const cached = JSON.parse(stored) as CachedResponse<T>;
      const age = Date.now() - cached.cachedAt;

      if (age > cached.ttl * 1000) {
        await this.cache.del(key);
        return null;
      }

      this.logger.debug({ key, ageMs: age }, 'Cache hit');
      return cached;
    } catch (err) {
      this.logger.warn({ key, err }, 'Cache read error');
      return null;
    }
  }

  /**
   * Store response in cache.
   */
  async set<T>(key: string, data: T, ttlSeconds?: number): Promise<void> {
    if (!key) return;

    const ttl = ttlSeconds ?? this.config.defaultTtlSeconds;
    const cached: CachedResponse<T> = {
      data,
      cachedAt: Date.now(),
      ttl,
    };

    try {
      await this.cache.set(key, JSON.stringify(cached), ttl);
      this.logger.debug({ key, ttl }, 'Cached response');
    } catch (err) {
      this.logger.warn({ key, err }, 'Cache write error');
    }
  }

  /**
   * Invalidate cache for a tenant or specific key.
   */
  async invalidate(tenantId: string, pattern?: string): Promise<void> {
    if (pattern) {
      // Delete specific key
      try {
        await this.cache.del(pattern);
        this.logger.debug({ pattern }, 'Cache invalidated');
      } catch (err) {
        this.logger.warn({ pattern, err }, 'Cache invalidation error');
      }
    } else {
      // Invalidate all keys for tenant (scan + delete)
      // Note: Full tenant invalidation requires KEYS or SCAN
      const prefix = `${this.config.prefix}:${tenantId}:*`;
      this.logger.warn({ prefix }, 'Full tenant cache invalidation not implemented - use pattern');
    }
  }

  /**
   * Check if a request should be cached.
   */
  shouldCache(method: string, path: string): boolean {
    if (!this.config.methods.includes(method.toUpperCase())) {
      return false;
    }

    // Don't cache paths with sensitive data
    const skipPaths = ['/auth/login', '/auth/signup', '/admin'];
    return !skipPaths.some((p) => path.startsWith(p));
  }

  private hashParams(params: Record<string, unknown>): string {
    if (!params || Object.keys(params).length === 0) {
      return 'empty';
    }

    const normalized = Object.keys(params)
      .sort()
      .reduce((acc, key) => {
        acc[key] = params[key];
        return acc;
      }, {} as Record<string, unknown>);

    return crypto.createHash('md5').update(JSON.stringify(normalized)).digest('hex').slice(0, 8);
  }
}
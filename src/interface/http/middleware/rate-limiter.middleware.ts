import { Injectable, Logger, NestMiddleware, Inject, Optional } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';

// ── Rate limit rule ────────────────────────────────────────────────────────────

export interface RateLimitRule {
  /** Unique tier name used in Redis key and metrics. */
  tier: string;
  /** Maximum requests allowed in the window. */
  limit: number;
  /** Window size in seconds. */
  windowSeconds: number;
  /** How to derive the bucket identifier from the request. */
  keyType: 'ip' | 'user';
}

// ── Per-route rate limit config (Section 17.1) ────────────────────────────────

/**
 * Maps route patterns to their rate limit rules.
 * Pattern format: "METHOD /path" — matched with startsWith for prefix routes.
 */
const ROUTE_RULES: Array<{ method: string; pathPrefix: string; rule: RateLimitRule }> = [
  {
    method: 'POST',
    pathPrefix: '/auth/login',
    rule: { tier: 'login', limit: 20, windowSeconds: 60, keyType: 'ip' },
  },
  {
    method: 'POST',
    pathPrefix: '/auth/signup',
    rule: { tier: 'signup', limit: 10, windowSeconds: 60, keyType: 'ip' },
  },
  {
    method: 'POST',
    pathPrefix: '/auth/otp/verify',
    rule: { tier: 'otp-verify', limit: 10, windowSeconds: 60, keyType: 'user' },
  },
  {
    method: 'POST',
    pathPrefix: '/auth/otp/send',
    rule: { tier: 'otp-send', limit: 5, windowSeconds: 60, keyType: 'user' },
  },
  {
    method: 'POST',
    pathPrefix: '/auth/password/reset/request',
    rule: { tier: 'pw-reset', limit: 3, windowSeconds: 60, keyType: 'ip' },
  },
  {
    method: 'POST',
    pathPrefix: '/auth/password/reset/confirm',
    rule: { tier: 'pw-reset-confirm', limit: 5, windowSeconds: 60, keyType: 'ip' },
  },
  {
    method: 'POST',
    pathPrefix: '/auth/refresh',
    rule: { tier: 'refresh', limit: 60, windowSeconds: 60, keyType: 'user' },
  },
  {
    method: 'POST',
    pathPrefix: '/auth/logout-all',
    rule: { tier: 'logout-all', limit: 10, windowSeconds: 60, keyType: 'user' },
  },
  {
    method: 'POST',
    pathPrefix: '/auth/logout',
    rule: { tier: 'logout', limit: 100, windowSeconds: 60, keyType: 'user' },
  },
];

// ── In-memory token bucket (fallback when Redis is unavailable) ───────────────

interface Bucket {
  tokens: number;
  lastRefill: number;
}

class InMemoryTokenBucket {
  private readonly buckets = new Map<string, Bucket>();

  /**
   * Attempt to consume one token from the bucket.
   * Returns { allowed, remaining, resetAt }.
   */
  consume(
    key: string,
    capacity: number,
    windowSeconds: number,
  ): { allowed: boolean; remaining: number; resetAt: number } {
    const now = Date.now();
    const windowMs = windowSeconds * 1000;

    let bucket = this.buckets.get(key);
    if (!bucket || now - bucket.lastRefill >= windowMs) {
      bucket = { tokens: capacity, lastRefill: now };
      this.buckets.set(key, bucket);
    }

    const resetAt = Math.ceil((bucket.lastRefill + windowMs) / 1000);

    if (bucket.tokens <= 0) {
      return { allowed: false, remaining: 0, resetAt };
    }

    bucket.tokens -= 1;
    return { allowed: true, remaining: bucket.tokens, resetAt };
  }

  /** Prune stale buckets to prevent unbounded memory growth. */
  prune(windowSeconds: number): void {
    const cutoff = Date.now() - windowSeconds * 1000 * 2;
    for (const [key, bucket] of this.buckets) {
      if (bucket.lastRefill < cutoff) {
        this.buckets.delete(key);
      }
    }
  }
}

// ── Middleware ─────────────────────────────────────────────────────────────────

@Injectable()
export class RateLimiterMiddleware implements NestMiddleware {
  private readonly logger = new Logger(RateLimiterMiddleware.name);
  private readonly fallback = new InMemoryTokenBucket();

  constructor(
    @Optional() @Inject(INJECTION_TOKENS.CACHE_PORT) private readonly cache?: ICachePort,
  ) {
    // Prune in-memory buckets every 5 minutes to avoid memory leaks.
    setInterval(() => this.fallback.prune(3600), 5 * 60 * 1000).unref();
  }

  async use(req: Request, res: Response, next: NextFunction): Promise<void> {
    const rule = this.matchRule(req);
    if (!rule) {
      return next();
    }

    const tenantId = (req as any).tenantId as string | undefined;
    const identifier = this.buildIdentifier(req, rule);
    const windowStart = Math.floor(Date.now() / 1000 / rule.windowSeconds) * rule.windowSeconds;
    const redisKey = `rl:${rule.tier}:${identifier}:${windowStart}`;

    // Apply adaptive multiplier (Section 12.6)
    const multiplier = await this.getAdaptiveMultiplier(tenantId);
    const effectiveLimit = Math.max(1, Math.floor(rule.limit * multiplier));

    let allowed: boolean;
    let remaining: number;
    let resetAt: number;

    const cacheAvailable = this.cache && !(this.isCacheCircuitOpen());

    if (cacheAvailable && this.cache) {
      ({ allowed, remaining, resetAt } = await this.consumeRedis(
        redisKey,
        effectiveLimit,
        rule.windowSeconds,
        windowStart,
      ));
    } else {
      // WAR-GRADE DEFENSE: Cost Critical / Auth Critical Rate Limits
      // If Redis is down, we must NOT fail-open or degrade to in-memory loosely on critical routes.
      // An attacker can drop the Redis pod and instantly bypass the global limits via horizontal scaling.
      if (rule.tier === 'otp-send' || rule.tier === 'signup' || rule.tier === 'pw-reset') {
        this.logger.error({ tier: rule.tier }, 'RATE LIMITER FAIL CLOSED: Redis unavailable for critical tier');

        // Strict fail closed
        res.setHeader('Retry-After', 30);
        res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Service is temporarily unavailable, please try again later.',
            retryable: true,
          },
          meta: {
            requestId: (req as any).id ?? '',
            timestamp: new Date().toISOString(),
            version: 'v1',
          },
        });
        return;
      }

      // Fallback: in-memory token bucket (per-pod, not distributed — Req 15.2)
      ({ allowed, remaining, resetAt } = this.fallback.consume(
        redisKey,
        effectiveLimit,
        rule.windowSeconds,
      ));
    }

    // Set standard rate limit headers
    res.setHeader('X-RateLimit-Limit', effectiveLimit);
    res.setHeader('X-RateLimit-Remaining', remaining);
    res.setHeader('X-RateLimit-Reset', resetAt);

    if (!allowed) {
      const retryAfter = resetAt - Math.floor(Date.now() / 1000);
      res.setHeader('Retry-After', Math.max(1, retryAfter));

      this.logger.warn(
        { tier: rule.tier, identifier, tenantId, multiplier },
        'Rate limit exceeded',
      );

      res.status(429).json({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          retryAfter: Math.max(1, retryAfter),
          retryable: true,
        },
        meta: {
          requestId: (req as any).id ?? '',
          timestamp: new Date().toISOString(),
          version: 'v1',
        },
      });
      return;
    }

    next();
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private matchRule(req: Request): RateLimitRule | null {
    const method = req.method.toUpperCase();
    const path = this.normalizePath(req.path);

    for (const entry of ROUTE_RULES) {
      if (entry.method === method && path.startsWith(entry.pathPrefix)) {
        return entry.rule;
      }
    }
    return null;
  }

  private buildIdentifier(req: Request, rule: RateLimitRule): string {
    if (rule.keyType === 'user') {
      // Prefer authenticated user ID; fall back to IP hash
      const userId = (req as any).user?.id ?? (req as any).userId;
      if (userId) {
        return `user:${userId}`;
      }
    }
    // IP-based: hash the IP to avoid storing raw IPs in Redis keys
    const ip = this.extractIp(req);
    return `ip:${crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16)}`;
  }

  private extractIp(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      return forwarded.split(',')[0]?.trim() ?? req.ip ?? 'unknown';
    }
    return req.ip ?? 'unknown';
  }

  private normalizePath(path: string): string {
    if (path.startsWith('/v1/')) {
      return path.replace('/v1', '');
    }
    return path;
  }

  /**
   * Redis-backed token bucket using Atomic Lua Script (INCR + EXPIRE).
   * Ensures that keys do not leak and cause permanent DoS if a crash happens
   * between INCR and EXPIRE.
   */
  private async consumeRedis(
    key: string,
    limit: number,
    windowSeconds: number,
    windowStart: number,
  ): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
    const resetAt = windowStart + windowSeconds;

    try {
      const luaScript = `
        local c = redis.call('incr', KEYS[1])
        if c == 1 then
          redis.call('expire', KEYS[1], ARGV[1])
        end
        return c
      `;
      const client = (this.cache as any).getClient?.();
      let count: number;

      if (client && typeof client.eval === 'function') {
        count = await client.eval(luaScript, 1, key, windowSeconds);
      } else {
        this.logger.warn('Atomic rate limiting unavailable: fallback to INCR+EXPIRE');
        count = await this.cache!.incr(key);
        if (count === 1) {
          await this.cache!.expire(key, windowSeconds);
        }
      }

      const remaining = Math.max(0, limit - count);
      const allowed = count <= limit;

      return { allowed, remaining, resetAt };
    } catch (err) {
      // Redis error — fall back to in-memory bucket
      this.logger.warn({ err }, 'Redis rate limit failed, falling back to in-memory');
      return this.fallback.consume(key, limit, windowSeconds);
    }
  }

  /**
   * Reads the adaptive rate limit multiplier for the tenant from Redis (Section 12.6).
   * Key: rate-limit-multiplier:{tenantId}
   * Falls back to 1.0 when unavailable.
   */
  private async getAdaptiveMultiplier(tenantId?: string): Promise<number> {
    if (!tenantId || !this.cache) {
      return 1.0;
    }

    try {
      const raw = await this.cache.get(`rate-limit-multiplier:${tenantId}`);
      if (raw === null) return 1.0;

      const value = parseFloat(raw);
      if (isNaN(value) || value <= 0) return 1.0;

      // Clamp to [0.3, 2.0] — never fully disable or excessively loosen limits
      return Math.max(0.3, Math.min(2.0, value));
    } catch {
      return 1.0;
    }
  }

  /**
   * Checks whether the Redis cache circuit breaker is open.
   * Uses duck-typing to avoid a hard dependency on RedisCacheAdapter.
   */
  private isCacheCircuitOpen(): boolean {
    return typeof (this.cache as any)?.isCircuitOpen === 'function'
      ? (this.cache as any).isCircuitOpen()
      : false;
  }
}

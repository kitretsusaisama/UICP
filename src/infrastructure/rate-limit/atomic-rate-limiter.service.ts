import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ICachePort } from '../../application/ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { Inject } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';

// ── Types ────────────────────────────────────────────────────────────────────

export interface RateLimitConfig {
  /** Unique tier name (e.g., 'login', 'signup'). */
  tier: string;
  /** Maximum requests per window. */
  limit: number;
  /** Window size in seconds. */
  windowSeconds: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
}

// ── Service ─────────────────────────────────────────────────────────────────

/**
 * AtomicRateLimiterService — provides atomic rate limiting using Lua scripts.
 *
 * Key features:
 * - Atomic INCR + EXPIRE via single Lua eval (no race condition)
 * - Fails closed on Redis errors (prevents unbounded traffic)
 * - Adaptive multiplier support for tenant-specific limits
 * - Circuit breaker to avoid cascading failures
 */
@Injectable()
export class AtomicRateLimiterService implements OnModuleInit {
  private readonly logger = new Logger(AtomicRateLimiterService.name);
  private luaScript: string | null = null;
  private circuitOpen = false;
  private circuitOpenSince = 0;
  private readonly CIRCUIT_RESET_MS = 30_000; // 30s

  constructor(
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {}

  onModuleInit(): void {
    this.loadLuaScript();
  }

  /**
   * Check rate limit for a given key and tier.
   * Returns { allowed, remaining, resetAt }.
   */
  async check(
    key: string,
    config: RateLimitConfig,
    tenantId?: string,
  ): Promise<RateLimitResult> {
    const now = Math.floor(Date.now() / 1000);
    const windowStart = Math.floor(now / config.windowSeconds) * config.windowSeconds;
    const resetAt = windowStart + config.windowSeconds;

    // Check circuit breaker
    if (this.circuitOpen) {
      if (Date.now() - this.circuitOpenSince > this.CIRCUIT_RESET_MS) {
        this.logger.warn('Circuit breaker attempting reset');
        this.circuitOpen = false;
      } else {
        // Circuit is open - fail closed
        return {
          allowed: false,
          remaining: 0,
          resetAt,
          retryAfter: Math.max(1, this.CIRCUIT_RESET_MS / 1000),
        };
      }
    }

    // Get adaptive multiplier for tenant
    const multiplier = await this.getAdaptiveMultiplier(tenantId);
    const effectiveLimit = Math.max(1, Math.floor(config.limit * multiplier));

    try {
      const result = await this.executeAtomicIncrement(key, effectiveLimit, config.windowSeconds);
      const count = typeof result === 'number' ? result : 0;
      const remaining = Math.max(0, effectiveLimit - count);
      const allowed = count !== -1 && count <= effectiveLimit;

      if (!allowed) {
        const retryAfter = resetAt - now;
        this.logger.warn(
          { tier: config.tier, key, count, limit: effectiveLimit },
          'Rate limit exceeded',
        );

        return {
          allowed: false,
          remaining: 0,
          resetAt,
          retryAfter: Math.max(1, retryAfter),
        };
      }

      return { allowed: true, remaining, resetAt };
    } catch (err) {
      // Redis error - fail closed for security-critical tiers
      this.handleError(err, config.tier);
      return {
        allowed: false,
        remaining: 0,
        resetAt,
        retryAfter: 30,
      };
    }
  }

  /**
   * Close the circuit breaker (for testing or manual reset).
   */
  closeCircuit(): void {
    this.circuitOpen = false;
    this.logger.log('Circuit breaker closed');
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private loadLuaScript(): void {
    try {
      const scriptPath = path.join(__dirname, 'sliding-window.lua');
      this.luaScript = fs.readFileSync(scriptPath, 'utf-8');
      this.logger.log('Lua script loaded successfully');
    } catch (err) {
      this.logger.error({ err }, 'Failed to load Lua script, using inline fallback');
      // Inline fallback if file not found
      this.luaScript = `
        local key = KEYS[1]
        local window = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local current = redis.call('GET', key)
        if current and tonumber(current) >= limit then
          return -1
        end
        local count = redis.call('INCR', key)
        if count == 1 then
          redis.call('EXPIRE', key, window)
        end
        return count
      `;
    }
  }

  private async executeAtomicIncrement(
    key: string,
    limit: number,
    windowSeconds: number,
  ): Promise<number | -1> {
    if (!this.luaScript) {
      throw new Error('Lua script not loaded');
    }

    // Get Redis client from cache port
    const redisClient = (this.cache as any).getClient?.();
    if (!redisClient || typeof redisClient.eval !== 'function') {
      throw new Error('Redis client not available');
    }

    const result = await redisClient.eval(
      this.luaScript,
      1, // number of keys
      key,
      windowSeconds,
      limit,
    );

    return result as number;
  }

  private async getAdaptiveMultiplier(tenantId?: string): Promise<number> {
    if (!tenantId) return 1.0;

    try {
      const raw = await this.cache.get(`rate-limit-multiplier:${tenantId}`);
      if (raw === null) return 1.0;

      const value = parseFloat(raw);
      if (isNaN(value) || value <= 0) return 1.0;

      return Math.max(0.3, Math.min(2.0, value));
    } catch {
      return 1.0;
    }
  }

  private handleError(err: unknown, tier: string): void {
    this.logger.error({ err, tier }, 'Redis rate limit error');

    // Only open circuit for non-critical tiers
    // Critical tiers (otp-send, signup, pw-reset) already fail-closed in middleware
    if (!this.circuitOpen) {
      this.circuitOpen = true;
      this.circuitOpenSince = Date.now();
    }
  }
}
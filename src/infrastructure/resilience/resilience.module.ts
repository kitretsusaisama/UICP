import { Module } from '@nestjs/common';
import { RetryBudget } from './retry-budget';
import { InMemoryRateLimiter } from './in-memory-rate-limiter';
import { MysqlSessionFallback } from './mysql-session-fallback';
import { MysqlAdvisoryLock } from './mysql-advisory-lock';

/**
 * Resilience module — circuit breakers, retry budget, and fallback adapters.
 *
 * Provides:
 * - RetryBudget: CLS-scoped retry budget (Req 15.5)
 * - InMemoryRateLimiter: fallback rate limiter when Redis is OPEN (Req 15.2)
 * - MysqlSessionFallback: fallback session store when Redis is OPEN (Req 15.2)
 * - MysqlAdvisoryLock: fallback distributed lock when Redis is OPEN (Req 15.2, 15.6)
 */
@Module({
  providers: [
    RetryBudget,
    InMemoryRateLimiter,
    MysqlSessionFallback,
    MysqlAdvisoryLock,
  ],
  exports: [
    RetryBudget,
    InMemoryRateLimiter,
    MysqlSessionFallback,
    MysqlAdvisoryLock,
  ],
})
export class ResilienceModule {}

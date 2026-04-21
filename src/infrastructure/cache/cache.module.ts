import { Global, Module } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { RedisCacheAdapter } from './redis-cache.adapter';
import { RedisOAuthAdapter, OAUTH_CACHE } from './redis-oauth.adapter';

/**
 * Global cache module — provides CACHE_PORT, the concrete RedisCacheAdapter, and IOAuthCache.
 * Marked @Global so all modules can inject CACHE_PORT without re-importing.
 */
@Global()
@Module({
  providers: [
    RedisCacheAdapter,
    { provide: INJECTION_TOKENS.CACHE_PORT, useExisting: RedisCacheAdapter },
    { provide: OAUTH_CACHE, useClass: RedisOAuthAdapter }
  ],
  exports: [RedisCacheAdapter, INJECTION_TOKENS.CACHE_PORT, OAUTH_CACHE],
})
export class CacheModule {}

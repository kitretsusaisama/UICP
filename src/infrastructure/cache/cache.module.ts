import { Global, Module } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { RedisCacheAdapter } from './redis-cache.adapter';

/**
 * Global cache module — provides CACHE_PORT and the concrete RedisCacheAdapter.
 * Marked @Global so all modules can inject CACHE_PORT without re-importing.
 */
@Global()
@Module({
  providers: [
    RedisCacheAdapter,
    { provide: INJECTION_TOKENS.CACHE_PORT, useExisting: RedisCacheAdapter },
  ],
  exports: [RedisCacheAdapter, INJECTION_TOKENS.CACHE_PORT],
})
export class CacheModule {}

import { Global, Module } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { RedisLockAdapter } from './redis-lock.adapter';

@Global()
@Module({
  providers: [
    RedisLockAdapter,
    { provide: INJECTION_TOKENS.LOCK_PORT, useExisting: RedisLockAdapter },
  ],
  exports: [RedisLockAdapter, INJECTION_TOKENS.LOCK_PORT],
})
export class LockModule {}

import { Global, Module } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { RedisSessionStore } from './redis-session.store';

@Global()
@Module({
  providers: [
    RedisSessionStore,
    { provide: INJECTION_TOKENS.SESSION_STORE, useExisting: RedisSessionStore },
  ],
  exports: [RedisSessionStore, INJECTION_TOKENS.SESSION_STORE],
})
export class SessionModule {}

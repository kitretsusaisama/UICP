import { Module } from '@nestjs/common';
import { ClsModule as NestjsClsModule, ClsService } from 'nestjs-cls';

/**
 * Typed CLS store interface.
 * All fields are optional because the store may be accessed before
 * the interceptor has populated it (e.g., during bootstrap health checks).
 */
export interface UicpClsStore {
  requestId?: string;
  tenantId?: string;
  tenantType?: string;
  isolationTier?: string;
  principalId?: string;
  membershipId?: string;
  actorId?: string;
  userId?: string;
  traceId?: string;
  sessionId?: string;
  policyVersion?: string;
  manifestVersion?: string;
}

export { ClsService };

@Module({
  imports: [
    NestjsClsModule.forRoot({
      global: true,
      middleware: {
        // Mount on all routes; the ClsContextInterceptor will populate the store
        mount: true,
        generateId: true,
        idGenerator: () => crypto.randomUUID(),
      },
    }),
  ],
  exports: [NestjsClsModule],
})
export class ClsModule {}

import { AuditExportWorker } from './workers/audit-export.worker';
import { Module } from '@nestjs/common';
import { BullMqQueueAdapter } from './bullmq-queue.adapter';
import { OtpSendWorker } from './workers/otp-send.worker';
import { AuditWriteWorker } from './workers/audit-write.worker';
import { SocAlertWorker } from './workers/soc-alert.worker';
import { OutboxRelayWorker } from './workers/outbox-relay.worker';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { OtpModule } from '../otp/otp.module';
import { RepositoriesModule } from '../db/mysql/repositories.module';

/**
 * QueueModule — wires BullMQ adapter and all workers.
 *
 * Workers are registered as providers so NestJS manages their lifecycle
 * (OnModuleInit / OnModuleDestroy hooks are called automatically).
 *
 * The BullMqQueueAdapter is exported so it can be injected as IQueuePort
 * in the application layer via the QUEUE_PORT injection token.
 */
@Module({
  imports: [OtpModule, RepositoriesModule],
  providers: [AuditExportWorker,
    BullMqQueueAdapter,
    {
      provide: INJECTION_TOKENS.QUEUE_PORT,
      useExisting: BullMqQueueAdapter,
    },
    OtpSendWorker,
    AuditWriteWorker,
    SocAlertWorker,
    OutboxRelayWorker,
  ],
  exports: [
    BullMqQueueAdapter,
    INJECTION_TOKENS.QUEUE_PORT,
  ],
})
export class QueueModule {}

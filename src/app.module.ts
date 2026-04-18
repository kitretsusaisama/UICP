import { Module } from '@nestjs/common';
import { PlatformOpsModule } from './infrastructure/platform-ops/platform-ops.module';
import { ClsModule } from 'nestjs-cls';

// Shared
import { LoggerModule } from './shared/logger/logger.module';
import { ConfigModule as SharedConfigModule } from './shared/config/config.module';

// Infrastructure
import { TracingModule } from './infrastructure/tracing/tracing.module';
import { MetricsModule } from './infrastructure/metrics/metrics.module';
import { CacheModule } from './infrastructure/cache/cache.module';
import { EncryptionModule } from './infrastructure/encryption/encryption.module';
import { MysqlModule } from './infrastructure/db/mysql/mysql.module';
import { RepositoriesModule } from './infrastructure/db/mysql/repositories.module';
import { SessionModule } from './infrastructure/session/session.module';
import { LockModule } from './infrastructure/lock/lock.module';
import { ResilienceModule } from './infrastructure/resilience/resilience.module';
import { QueueModule } from './infrastructure/queue/queue.module';

// Application
import { ApplicationModule } from './application/application.module';

import { OtpModule } from './infrastructure/otp/otp.module';
import { HttpModule } from './interface/http/http.module';
import { GrpcModule } from './interface/grpc/grpc.module';

import { SocAlertWorker } from './infrastructure/queue/workers/soc-alert.worker';
import { AuditWriteWorker } from './infrastructure/queue/workers/audit-write.worker';
import { OtpSendWorker } from './infrastructure/queue/workers/otp-send.worker';
import { OutboxRelayWorker } from './infrastructure/queue/workers/outbox-relay.worker';
import { SocDashboardGateway } from './interface/ws/soc-dashboard.gateway';

@Module({
  imports: [
    // ── Global config (Zod-validated) ──────────────────────────────────────
    SharedConfigModule,

    // ── CLS — request-scoped context propagation ───────────────────────────
    ClsModule.forRoot({
      global: true,
      middleware: {
        mount: true,
        generateId: true,
        idGenerator: () => crypto.randomUUID(),
      },
    }),

    // ── Logging ────────────────────────────────────────────────────────────
    LoggerModule,

    // ── Observability ──────────────────────────────────────────────────────
    TracingModule,
    MetricsModule,

    // ── Infrastructure: cache + DB + encryption ────────────────────────────
    CacheModule,
    EncryptionModule,
    MysqlModule.forRoot(),
    RepositoriesModule,
    SessionModule,
    LockModule,
    ResilienceModule,
    QueueModule,
    OtpModule,

    // ── Application layer ──────────────────────────────────────────────────
    ApplicationModule,

    // ── Interface layer ────────────────────────────────────────────────────
    HttpModule,
    GrpcModule,
  ],
  providers: [
    SocAlertWorker,
    AuditWriteWorker,
    OtpSendWorker,
    OutboxRelayWorker,
    SocDashboardGateway,
  ]
})
export class AppModule {}

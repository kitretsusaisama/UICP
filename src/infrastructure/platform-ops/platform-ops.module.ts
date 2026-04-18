import { Module } from '@nestjs/common';
import { MetricsService } from '../../application/services/platform-ops/metrics.service';
import { HealthService } from '../../application/services/platform-ops/health.service';
import { StatusService } from '../../application/services/platform-ops/status.service';
import { VersionService } from '../../application/services/platform-ops/version.service';

import { MetricsController } from '../../interface/http/controllers/platform-ops/metrics.controller';
import { HealthController } from '../../interface/http/controllers/platform-ops/health.controller';
import { StatusController } from '../../interface/http/controllers/platform-ops/status.controller';
import { VersionController } from '../../interface/http/controllers/platform-ops/version.controller';
import { OpenApiController } from '../../interface/http/controllers/platform-ops/openapi.controller';

import { QueueModule } from '../queue/queue.module';
import { CacheModule } from '../cache/cache.module';

@Module({
  imports: [QueueModule, CacheModule],
  controllers: [
    MetricsController,
    HealthController,
    StatusController,
    VersionController,
    OpenApiController
  ],
  providers: [
    MetricsService,
    HealthService,
    StatusService,
    VersionService
  ],
  exports: [MetricsService]
})
export class PlatformOpsModule {}

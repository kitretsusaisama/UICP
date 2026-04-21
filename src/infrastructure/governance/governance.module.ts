import { ResilientProvider } from './resilience/resilient-provider';
import { CircuitBreakerService } from './resilience/circuit-breaker';
import { QueueModule } from '../queue/queue.module';
import { AuditInterceptor } from './interceptors/audit.interceptor';
import { Module } from '@nestjs/common';
import { DiscoveryModule } from '@nestjs/core';
import { GovernanceBootstrapValidator } from './bootstrap/governance.bootstrap';
import { GovernanceGuard } from './guards/governance.guard';
import { InternalServiceGuard } from '../../interface/http/guards/internal-service.guard';
import { PolicyService } from '../../application/services/governance/policy.service';
import { RoleService } from '../../application/services/governance/role.service';
import { CacheModule } from '../cache/cache.module';
import { DatabaseModule } from '../db/mysql/database.module';

@Module({
  imports: [DiscoveryModule, CacheModule, DatabaseModule, QueueModule],
  providers: [
    InternalServiceGuard,
    GovernanceBootstrapValidator,
    GovernanceGuard,
    PolicyService,
    RoleService
  ],
  exports: [InternalServiceGuard, GovernanceGuard, PolicyService, RoleService, ResilientProvider, CircuitBreakerService]
})
export class GovernanceModule {}

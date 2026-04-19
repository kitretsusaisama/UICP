import { Module } from '@nestjs/common';
import { ExtensionRegistryService } from '../../application/services/extensions/extension.registry';
import { ExtensionExecutorService } from '../../application/services/extensions/extension.executor';
import { ExtensionsController } from './../interface/http/controllers/extensions/extensions.controller';
import { ExtensionsExecutionController } from './../interface/http/controllers/extensions/extensions-execution.controller';
import { GovernanceModule } from '../governance/governance.module';
import { CacheModule } from '../cache/cache.module';
import { PlatformModule } from '../platform/platform.module';
import { PlatformOpsModule } from '../platform-ops/platform-ops.module';

@Module({
  imports: [GovernanceModule, CacheModule, PlatformModule, PlatformOpsModule],
  controllers: [ExtensionsController, ExtensionsExecutionController],
  providers: [ExtensionRegistryService, ExtensionExecutorService],
  exports: [ExtensionRegistryService, ExtensionExecutorService]
})
export class ExtensionsModule {}

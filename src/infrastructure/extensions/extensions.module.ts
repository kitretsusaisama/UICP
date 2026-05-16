import { Module } from '@nestjs/common';
import { ExtensionExecutorService } from '../../application/services/extensions/extension.executor';
import { ExtensionRegistryService } from '../../application/services/extensions/extension.registry';

@Module({
  providers: [ExtensionExecutorService, ExtensionRegistryService],
  exports: [ExtensionExecutorService, ExtensionRegistryService],
})
export class ExtensionsModule {}

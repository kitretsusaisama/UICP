import { Controller, Get, Param } from '@nestjs/common';
import { ExtensionRegistryService } from '../../../../application/services/extensions/extension.registry';

@Controller('v1/extensions')
export class ExtensionsController {
  constructor(private readonly registry: ExtensionRegistryService) {}

  @Get(':extensionKey/schema')
  async schema(@Param('extensionKey') extensionKey: string) {
    return {
      data: {
        extensionKey,
        commands: [],
      },
    };
  }

  @Get(':extensionKey/bindings')
  async bindings(@Param('extensionKey') extensionKey: string) {
    return {
      data: {
        extensionKey,
        bindings: [],
      },
    };
  }
}

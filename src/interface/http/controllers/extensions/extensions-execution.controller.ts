import { Body, Controller, Headers, Param, Post } from '@nestjs/common';
import { ExtensionExecutorService } from '../../../../application/services/extensions/extension.executor';

@Controller('v1/extensions/:extensionKey')
export class ExtensionsExecutionController {
  constructor(private readonly executor: ExtensionExecutorService) {}

  @Post('commands/:commandKey')
  async execute(
    @Headers('x-tenant-id') tenantId: string,
    @Param('extensionKey') extensionKey: string,
    @Param('commandKey') commandKey: string,
    @Body() payload: unknown,
  ) {
    return {
      data: await this.executor.execute({
        tenantId,
        extensionKey,
        commandKey,
        payload,
      }),
    };
  }
}

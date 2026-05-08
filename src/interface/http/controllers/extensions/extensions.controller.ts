import { Controller, Get, Param, UseGuards, Request, NotFoundException } from '@nestjs/common';
import { ExtensionRegistryService } from '../../../../src/application/services/extensions/extension.registry';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { TenantGuard } from '../../guards/tenant.guard';
import { zodToJsonSchema } from 'zod-to-json-schema';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';

@ApiTags('Extensions')
@Controller('v1/extensions')
export class ExtensionsController {
  constructor(private readonly registry: ExtensionRegistryService) {}

  @Get(':extensionKey/schema')
  @UseGuards(JwtAuthGuard, TenantGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Discover extension capabilities and JSON schemas' })
  getSchema(@Param('extensionKey') extensionKey: string) {
    const ext = this.registry.getExtension(extensionKey);

    return {
      success: true,
      data: {
        extensionKey: ext.extensionKey,
        version: ext.version,
        commands: ext.commands.map(cmd => ({
          commandKey: cmd.commandKey,
          inputSchema: zodToJsonSchema(cmd.inputSchema, `${cmd.commandKey}Input`),
          outputSchema: zodToJsonSchema(cmd.outputSchema, `${cmd.commandKey}Output`),
          rateLimit: `${cmd.rateLimitConfig.limit}/${cmd.rateLimitConfig.window}s`,
          requiresSignature: cmd.requiresSignature,
          requiredPermission: cmd.requiredPermission
        }))
      }
    };
  }

  @Get(':extensionKey/bindings')
  @UseGuards(JwtAuthGuard, TenantGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Discover external resource bindings (Safe metadata only)' })
  getBindings(@Param('extensionKey') extensionKey: string) {
    const ext = this.registry.getExtension(extensionKey);

    return {
      success: true,
      data: {
        extensionKey: ext.extensionKey,
        bindings: ext.bindings
      }
    };
  }
}

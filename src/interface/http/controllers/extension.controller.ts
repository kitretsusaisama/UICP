import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  Param,
  Post,
} from '@nestjs/common';
import { ApiHeader, ApiTags } from '@nestjs/swagger';
import { TenantManifestService } from '../../../application/control-plane/services/tenant-manifest.service';
import { ExtensionDispatcherService } from '../../../application/dynamic-api/services/extension-dispatcher.service';

function parseTenantId(raw: string | undefined): string {
  if (!raw) {
    throw new BadRequestException({
      error: { code: 'MISSING_TENANT_ID', message: 'X-Tenant-ID header is required' },
    });
  }
  return raw;
}

@ApiTags('Extensions')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/extensions')
export class ExtensionController {
  constructor(
    private readonly manifestService: TenantManifestService,
    private readonly extensionDispatcher: ExtensionDispatcherService,
  ) {}

  @Post(':extensionKey/commands/:commandKey')
  async execute(
    @Headers('x-tenant-id') rawTenantId: string,
    @Param('extensionKey') extensionKey: string,
    @Param('commandKey') commandKey: string,
    @Body() body: Record<string, unknown>,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const effectiveManifest = await this.manifestService.resolveEffectiveManifest(tenantId);
    const owningModule = Object.values(effectiveManifest.modules).find((module) =>
      module.extensions.some((item) => item.key === extensionKey),
    );
    const extension = owningModule?.extensions.find((item) => item.key === extensionKey);

    if (!extension) {
      throw new BadRequestException({
        error: { code: 'EXTENSION_NOT_ENABLED', message: `Extension ${extensionKey} is not enabled` },
      });
    }

    return {
      data: await this.extensionDispatcher.execute({
        tenantId,
        moduleKey: owningModule!.moduleKey,
        extensionKey,
        commandKey,
        body,
      }),
    };
  }

  @Get(':extensionKey/bindings')
  async bindings(
    @Headers('x-tenant-id') rawTenantId: string,
    @Param('extensionKey') extensionKey: string,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const effectiveManifest = await this.manifestService.resolveEffectiveManifest(tenantId);
    const owningModule = Object.values(effectiveManifest.modules).find((module) =>
      module.extensions.some((item) => item.key === extensionKey),
    );
    if (!owningModule) {
      throw new BadRequestException({
        error: { code: 'EXTENSION_NOT_ENABLED', message: `Extension ${extensionKey} is not enabled` },
      });
    }

    return {
      data: await this.extensionDispatcher.getBindingSchema(tenantId, owningModule.moduleKey, extensionKey),
    };
  }

  @Get(':extensionKey/schema')
  async schema(
    @Headers('x-tenant-id') rawTenantId: string,
    @Param('extensionKey') extensionKey: string,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const effectiveManifest = await this.manifestService.resolveEffectiveManifest(tenantId);
    const owningModule = Object.values(effectiveManifest.modules).find((module) =>
      module.extensions.some((item) => item.key === extensionKey),
    );
    if (!owningModule) {
      throw new BadRequestException({
        error: { code: 'EXTENSION_NOT_ENABLED', message: `Extension ${extensionKey} is not enabled` },
      });
    }

    return {
      data: await this.extensionDispatcher.getBindingSchema(tenantId, owningModule.moduleKey, extensionKey),
    };
  }
}

import { BadRequestException, Body, Controller, Get, Headers, Post } from '@nestjs/common';
import { ApiHeader, ApiTags } from '@nestjs/swagger';
import { TenantManifestService } from '../../../application/control-plane/services/tenant-manifest.service';
import { ProviderRoutingService } from '../../../application/control-plane/services/provider-routing.service';
import { ExtensionDispatcherService } from '../../../application/dynamic-api/services/extension-dispatcher.service';
import { ProviderRegistryService } from '../../../infrastructure/providers/provider-registry.service';

function parseTenantId(raw: string | undefined): string {
  if (!raw) {
    throw new BadRequestException({
      error: { code: 'MISSING_TENANT_ID', message: 'X-Tenant-ID header is required' },
    });
  }
  return raw;
}

@ApiTags('Platform')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/platform')
export class PlatformController {
  constructor(
    private readonly manifestService: TenantManifestService,
    private readonly providerRoutingService: ProviderRoutingService,
    private readonly extensionDispatcher: ExtensionDispatcherService,
    private readonly providerRegistry: ProviderRegistryService,
  ) {}

  @Get('discovery')
  async discovery(@Headers('x-tenant-id') rawTenantId: string) {
    const tenantId = parseTenantId(rawTenantId);
    const effectiveManifest = await this.manifestService.resolveEffectiveManifest(tenantId);

    return {
      data: {
        tenantId,
        manifestVersion: effectiveManifest.versionHash,
        modules: Object.values(effectiveManifest.modules).map((module) => ({
          moduleKey: module.moduleKey,
          description: module.description,
          commands: module.commands.map((command) => command.key),
          resources: module.resources.map((resource) => resource.key),
          actions: module.actions.map((action) => action.key),
          extensions: module.extensions.map((extension) => extension.key),
        })),
        providers: this.providerRegistry.listProviders(),
      },
    };
  }

  @Get('openapi')
  async openapi(@Headers('x-tenant-id') rawTenantId: string) {
    const tenantId = parseTenantId(rawTenantId);
    const effectiveManifest = await this.manifestService.resolveEffectiveManifest(tenantId);

    return {
      data: {
        tenantId,
        manifestVersion: effectiveManifest.versionHash,
        projectedSpec: {
          openapi: '3.1.0',
          info: {
            title: 'Tenant Projected API',
            version: effectiveManifest.versionHash,
          },
          modules: effectiveManifest.modules,
        },
      },
    };
  }

  @Get('sdk-descriptor')
  async sdkDescriptor(@Headers('x-tenant-id') rawTenantId: string) {
    const tenantId = parseTenantId(rawTenantId);
    const effectiveManifest = await this.manifestService.resolveEffectiveManifest(tenantId);

    return {
      data: {
        tenantId,
        manifestVersion: effectiveManifest.versionHash,
        sdk: {
          profile: 'tenant-runtime',
          modules: Object.values(effectiveManifest.modules).map((module) => ({
            key: module.moduleKey,
            commands: module.commands,
            resources: module.resources,
            actions: module.actions,
          })),
        },
      },
    };
  }

  @Get('manifest')
  async manifest(@Headers('x-tenant-id') rawTenantId: string) {
    const tenantId = parseTenantId(rawTenantId);
    return {
      data: await this.manifestService.resolveEffectiveManifest(tenantId),
    };
  }

  @Post('manifest/preview')
  async manifestPreview(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body() body: { moduleKey?: string; override?: Record<string, unknown> },
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const effectiveManifest = await this.manifestService.resolveEffectiveManifest(tenantId);
    const moduleKey = body.moduleKey;
    return {
      data: {
        tenantId,
        manifestVersion: effectiveManifest.versionHash,
        moduleKey,
        current: moduleKey ? effectiveManifest.modules[moduleKey] ?? null : effectiveManifest.modules,
        previewOverride: body.override ?? {},
      },
    };
  }

  @Post('provider-routing/preview')
  async providerRoutePreview(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body() body: { channel: 'SMS' | 'EMAIL'; purpose: string },
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const route = await this.providerRoutingService.resolveRoute(tenantId, body.channel, body.purpose as any);
    return { data: route };
  }

  @Post('extensions/preview')
  async extensionPreview(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body() body: { moduleKey: string; extensionPoint: string },
  ) {
    const tenantId = parseTenantId(rawTenantId);
    return {
      data: await this.extensionDispatcher.getBindingSchema(tenantId, body.moduleKey, body.extensionPoint),
    };
  }
}

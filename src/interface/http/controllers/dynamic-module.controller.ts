import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiHeader, ApiTags } from '@nestjs/swagger';
import { TenantManifestService } from '../../../application/control-plane/services/tenant-manifest.service';
import { ManifestSchemaField } from '../../../application/control-plane/contracts/effective-manifest.contract';
import { DynamicCommandRegistryService } from '../../../application/dynamic-api/services/dynamic-command-registry.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';

function parseTenantId(raw: string | undefined): string {
  if (!raw) {
    throw new BadRequestException({
      error: { code: 'MISSING_TENANT_ID', message: 'X-Tenant-ID header is required' },
    });
  }
  return raw;
}

function validateFields(body: Record<string, unknown>, schema: ManifestSchemaField[] = []): void {
  for (const field of schema) {
    if (field.required && !(field.key in body)) {
      throw new BadRequestException({
        error: {
          code: 'INVALID_DYNAMIC_COMMAND',
          message: `Missing required field: ${field.key}`,
        },
      });
    }
    if (!(field.key in body)) {
      continue;
    }
    const value = body[field.key];
    const actualType = Array.isArray(value) ? 'array' : typeof value;
    const expectedType = field.type;
    if (
      value !== null &&
      ((expectedType === 'array' && !Array.isArray(value)) ||
        (expectedType === 'object' && (Array.isArray(value) || actualType !== 'object')) ||
        (expectedType !== 'array' && expectedType !== 'object' && actualType !== expectedType))
    ) {
      throw new BadRequestException({
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `Field ${field.key} must be of type ${field.type}`,
        },
      });
    }
  }
}

interface DynamicRequest {
  headers: Record<string, string | string[] | undefined>;
  principalId?: string;
  membershipId?: string;
  actorId?: string;
  sessionId?: string;
  capabilities?: string[];
  perms?: string[];
}

@ApiTags('Dynamic Modules')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/modules')
@UseGuards(JwtAuthGuard)
export class DynamicModuleController {
  constructor(
    private readonly manifestService: TenantManifestService,
    private readonly commandRegistry: DynamicCommandRegistryService,
  ) {}

  @Get(':moduleKey/resources/:resourceKey')
  async getResource(
    @Headers('x-tenant-id') rawTenantId: string,
    @Param('moduleKey') moduleKey: string,
    @Param('resourceKey') resourceKey: string,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const effectiveManifest = await this.manifestService.resolveEffectiveManifest(tenantId);
    const module = effectiveManifest.modules[moduleKey];
    const resource = module?.resources.find((item) => item.key === resourceKey);
    if (!module || !resource) {
      throw new BadRequestException({
        error: { code: 'RESOURCE_NOT_ENABLED', message: `Resource ${moduleKey}.${resourceKey} is not enabled` },
      });
    }

    return {
      data: {
        tenantId,
        manifestVersion: effectiveManifest.versionHash,
        moduleKey,
        resource,
      },
    };
  }

  @Post(':moduleKey/commands/:commandKey')
  async executeCommand(
    @Headers('x-tenant-id') rawTenantId: string,
    @Param('moduleKey') moduleKey: string,
    @Param('commandKey') commandKey: string,
    @Body() body: Record<string, unknown>,
    @Req() req: DynamicRequest,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const effectiveManifest = await this.manifestService.resolveEffectiveManifest(tenantId);
    const module = effectiveManifest.modules[moduleKey];
    const command = module?.commands.find((item) => item.key === commandKey);
    if (!module || !command) {
      throw new BadRequestException({
        error: { code: 'COMMAND_NOT_ENABLED', message: `Command ${moduleKey}.${commandKey} is not enabled` },
      });
    }

    validateFields(body, command.requestSchema);

    const result = await this.commandRegistry.execute(
      moduleKey,
      commandKey,
      command.capability,
      command.stepUpRequired,
      body,
      {
        tenantId,
        principalId: req.principalId,
        membershipId: req.membershipId,
        actorId: req.actorId,
        sessionId: req.sessionId,
        capabilities: req.capabilities,
        perms: req.perms,
      },
    );

    return {
      data: {
        tenantId,
        manifestVersion: effectiveManifest.versionHash,
        moduleKey,
        commandKey,
        capability: command.capability,
        stepUpRequired: command.stepUpRequired ?? false,
        result,
      },
    };
  }

  @Post(':moduleKey/actions/:actionKey')
  async getAction(
    @Headers('x-tenant-id') rawTenantId: string,
    @Param('moduleKey') moduleKey: string,
    @Param('actionKey') actionKey: string,
    @Body() body: Record<string, unknown>,
    @Req() req: DynamicRequest,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const effectiveManifest = await this.manifestService.resolveEffectiveManifest(tenantId);
    const module = effectiveManifest.modules[moduleKey];
    const action = module?.actions.find((item) => item.key === actionKey);
    if (!module || !action) {
      throw new BadRequestException({
        error: { code: 'ACTION_NOT_ENABLED', message: `Action ${moduleKey}.${actionKey} is not enabled` },
      });
    }

    const result = await this.commandRegistry.execute(
      moduleKey,
      actionKey,
      action.capability,
      false,
      body,
      {
        tenantId,
        principalId: req.principalId,
        membershipId: req.membershipId,
        actorId: req.actorId,
        sessionId: req.sessionId,
        capabilities: req.capabilities,
        perms: req.perms,
      },
    );

    return {
      data: {
        tenantId,
        manifestVersion: effectiveManifest.versionHash,
        moduleKey,
        action,
        result,
      },
    };
  }
}

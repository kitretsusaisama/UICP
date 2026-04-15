import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import {
  ExtensionBindingRecord,
  IExtensionBindingRepository,
} from '../../ports/driven/i-extension-binding.repository';

export interface ExtensionExecutionContext {
  tenantId: string;
  moduleKey: string;
  extensionKey: string;
  commandKey: string;
  body: Record<string, unknown>;
  isolationTier?: string;
}

@Injectable()
export class ExtensionDispatcherService {
  constructor(
    @Inject(INJECTION_TOKENS.EXTENSION_BINDING_REPOSITORY)
    private readonly extensionBindingRepository: IExtensionBindingRepository,
  ) {}

  async execute(context: ExtensionExecutionContext): Promise<Record<string, unknown>> {
    const binding = await this.extensionBindingRepository.findActiveBinding(
      context.tenantId,
      context.moduleKey,
      context.extensionKey,
    );
    if (!binding) {
      throw new BadRequestException({
        error: {
          code: 'EXTENSION_BINDING_MISSING',
          message: `No active binding found for ${context.moduleKey}.${context.extensionKey}`,
        },
      });
    }

    this.assertRuntimeTarget(binding, context.isolationTier);

    if (binding.handler.handlerRef === 'platform.echo') {
      return {
        accepted: true,
        extensionKey: context.extensionKey,
        commandKey: context.commandKey,
        tenantId: context.tenantId,
        runtimeTarget: binding.handler.runtimeTarget,
        bindingId: binding.id,
        config: binding.configJson ? JSON.parse(binding.configJson) : {},
        echoedBody: context.body,
      };
    }

    if (binding.handler.handlerRef === 'notification.payload.enricher') {
      return {
        accepted: true,
        extensionKey: context.extensionKey,
        commandKey: context.commandKey,
        tenantId: context.tenantId,
        runtimeTarget: binding.handler.runtimeTarget,
        bindingId: binding.id,
        enrichedPayload: {
          ...(binding.configJson ? JSON.parse(binding.configJson) : {}),
          ...context.body,
        },
      };
    }

    throw new BadRequestException({
      error: {
        code: 'EXTENSION_HANDLER_NOT_REGISTERED',
        message: `Handler ref ${binding.handler.handlerRef} is not registered in the shared runtime`,
      },
    });
  }

  async getBindingSchema(
    tenantId: string,
    moduleKey: string,
    extensionPoint: string,
  ): Promise<Record<string, unknown> | null> {
    const binding = await this.extensionBindingRepository.findActiveBinding(tenantId, moduleKey, extensionPoint);
    if (!binding) {
      return null;
    }

    return {
      bindingId: binding.id,
      version: binding.version,
      extensionPoint: binding.extensionPoint,
      handler: binding.handler,
      config: binding.configJson ? JSON.parse(binding.configJson) : {},
    };
  }

  private assertRuntimeTarget(binding: ExtensionBindingRecord, isolationTier?: string): void {
    if (binding.handler.runtimeTarget === 'shared') {
      return;
    }

    if (isolationTier === 'dedicated_runtime') {
      return;
    }

    throw new BadRequestException({
      error: {
        code: 'EXTENSION_RUNTIME_NOT_ALLOWED',
        message: `Runtime target ${binding.handler.runtimeTarget} is not allowed for isolation tier ${isolationTier ?? 'shared'}`,
      },
    });
  }
}

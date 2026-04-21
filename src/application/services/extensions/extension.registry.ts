import { Injectable, NotFoundException } from '@nestjs/common';
import { z } from 'zod';

export interface CommandContext {
  tenantId: string;
  appId: string;
  actorId: string;
  requestId: string;
}

export type CommandHandler = (ctx: CommandContext, input: any) => Promise<any>;

export interface ExtensionCommandMetadata {
  commandKey: string;
  inputSchema: z.ZodSchema;
  outputSchema: z.ZodSchema;
  rateLimitConfig: { limit: number; window: number }; // e.g. 100 req per 60s
  requiresSignature: boolean;
  requiredPermission: string;
}

export interface ExtensionMetadata {
  extensionKey: string;
  version: string;
  commands: ExtensionCommandMetadata[];
  bindings: {
    events: string[];
    permissions: string[];
    resources: string[];
  };
}

@Injectable()
export class ExtensionRegistryService {
  private metadata: Map<string, ExtensionMetadata> = new Map();
  private handlers: Map<string, CommandHandler> = new Map(); // Key format: `extensionKey:commandKey`

  constructor() {
    this.registerDefaults();
  }

  private registerDefaults() {
    // Scaffold deterministic "billing.createInvoice"
    this.registerExtension({
      extensionKey: 'billing',
      version: '1.0.0',
      bindings: {
        events: ['invoice.created'],
        permissions: ['billing.invoice.create'],
        resources: ['billing-db']
      },
      commands: [
        {
          commandKey: 'createInvoice.v1',
          inputSchema: z.object({
            amount: z.number().positive(),
            currency: z.string().length(3),
            customerId: z.string().optional()
          }).strict(),
          outputSchema: z.object({
            invoiceId: z.string()
          }),
          rateLimitConfig: { limit: 10, window: 60 },
          requiresSignature: true,
          requiredPermission: 'billing.invoice.create'
        }
      ]
    });

    this.registerHandler('billing', 'createInvoice.v1', async (ctx, input) => {
      // Deterministic, safe static handler execution
      return { invoiceId: `inv_${Date.now()}_${ctx.tenantId}` };
    });
  }

  public registerExtension(meta: ExtensionMetadata) {
    this.metadata.set(meta.extensionKey, meta);
  }

  public registerHandler(extensionKey: string, commandKey: string, handler: CommandHandler) {
    this.handlers.set(`${extensionKey}:${commandKey}`, handler);
  }

  public getExtension(extensionKey: string): ExtensionMetadata {
    const ext = this.metadata.get(extensionKey);
    if (!ext) throw new NotFoundException(`Extension ${extensionKey} not found`);
    return ext;
  }

  public getCommandMetadata(extensionKey: string, commandKey: string): ExtensionCommandMetadata {
    const ext = this.getExtension(extensionKey);
    const cmd = ext.commands.find(c => c.commandKey === commandKey);
    if (!cmd) throw new NotFoundException(`Command ${commandKey} not found in extension ${extensionKey}`);
    return cmd;
  }

  public getHandler(extensionKey: string, commandKey: string): CommandHandler {
    const handler = this.handlers.get(`${extensionKey}:${commandKey}`);
    if (!handler) throw new NotFoundException(`No handler mapped for ${extensionKey}:${commandKey}`);
    return handler;
  }
}

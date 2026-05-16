import { Injectable } from '@nestjs/common';

export interface ExtensionExecutionRequest {
  tenantId: string;
  extensionKey: string;
  commandKey: string;
  payload: unknown;
  actorId?: string;
}

@Injectable()
export class ExtensionExecutorService {
  async execute(request: ExtensionExecutionRequest) {
    return {
      accepted: true,
      tenantId: request.tenantId,
      extensionKey: request.extensionKey,
      commandKey: request.commandKey,
      result: null,
    };
  }
}

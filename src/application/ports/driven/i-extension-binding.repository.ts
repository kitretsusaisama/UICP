export interface ExtensionBindingRecord {
  id: string;
  tenantId: string;
  moduleKey: string;
  extensionPoint: string;
  status: string;
  version: number;
  configJson?: string;
  handler: {
    id: string;
    extensionKey: string;
    kind: string;
    runtimeTarget: 'shared' | 'isolated';
    contractVersion: string;
    handlerRef: string;
    status: string;
  };
}

export interface IExtensionBindingRepository {
  findActiveBinding(
    tenantId: string,
    moduleKey: string,
    extensionPoint: string,
  ): Promise<ExtensionBindingRecord | null>;
}

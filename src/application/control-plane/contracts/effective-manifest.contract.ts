export interface ManifestSchemaField {
  key: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  required?: boolean;
  description?: string;
}

export interface ManifestCommandContract {
  key: string;
  description: string;
  capability: string;
  stepUpRequired?: boolean;
  requestSchema?: ManifestSchemaField[];
  responseSchema?: ManifestSchemaField[];
  extensionHooks?: string[];
}

export interface ManifestResourceContract {
  key: string;
  description: string;
  capability?: string;
  fields?: ManifestSchemaField[];
}

export interface ManifestActionContract {
  key: string;
  description: string;
  capability: string;
}

export interface ManifestExtensionContract {
  key: string;
  description: string;
  extensionPoint: string;
  runtimeTarget: 'shared' | 'isolated';
}

export interface ModuleManifestContract {
  moduleKey: string;
  version: string;
  description: string;
  resources: ManifestResourceContract[];
  commands: ManifestCommandContract[];
  actions: ManifestActionContract[];
  extensions: ManifestExtensionContract[];
  docs?: {
    summary?: string;
  };
}

export interface EffectiveManifest {
  tenantId: string;
  versionHash: string;
  modules: Record<string, ModuleManifestContract>;
}

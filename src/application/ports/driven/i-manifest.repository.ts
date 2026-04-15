export interface ModuleManifestRecord {
  moduleKey: string;
  version: string;
  manifestJson: string;
  status: 'draft' | 'active' | 'archived';
  updatedAt: Date;
}

export interface TenantManifestOverrideRecord {
  tenantId: string;
  moduleKey: string;
  version: string;
  overrideJson: string;
  status: 'draft' | 'active' | 'archived';
  updatedAt: Date;
}

export interface IManifestRepository {
  listActiveModuleManifests(): Promise<ModuleManifestRecord[]>;
  listTenantOverrides(tenantId: string): Promise<TenantManifestOverrideRecord[]>;
}

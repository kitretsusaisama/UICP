import { Inject, Injectable } from '@nestjs/common';
import {
  IManifestRepository,
  ModuleManifestRecord,
  TenantManifestOverrideRecord,
} from '../../../application/ports/driven/i-manifest.repository';
import { MYSQL_POOL, DbPool } from './mysql.module';

function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

interface ModuleManifestRow {
  module_key: string;
  version: string;
  manifest_json: string;
  status: 'draft' | 'active' | 'archived';
  updated_at: Date;
}

interface TenantManifestOverrideRow {
  tenant_id: Buffer;
  module_key: string;
  version: string;
  override_json: string;
  status: 'draft' | 'active' | 'archived';
  updated_at: Date;
}

function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

@Injectable()
export class MysqlManifestRepository implements IManifestRepository {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async listActiveModuleManifests(): Promise<ModuleManifestRecord[]> {
    const [rows] = await this.pool.execute<ModuleManifestRow[]>(
      `SELECT module_key, version, manifest_json, status, updated_at
         FROM module_manifests
        WHERE status = 'active'`,
    );

    return rows.map((row) => ({
      moduleKey: row.module_key,
      version: row.version,
      manifestJson: typeof row.manifest_json === 'string' ? row.manifest_json : JSON.stringify(row.manifest_json),
      status: row.status,
      updatedAt: row.updated_at,
    }));
  }

  async listTenantOverrides(tenantId: string): Promise<TenantManifestOverrideRecord[]> {
    const [rows] = await this.pool.execute<TenantManifestOverrideRow[]>(
      `SELECT tenant_id, module_key, version, override_json, status, updated_at
         FROM tenant_manifest_overrides
        WHERE tenant_id = ?
          AND status = 'active'`,
      [uuidToBuffer(tenantId)],
    );

    return rows.map((row) => ({
      tenantId: bufferToUuid(row.tenant_id),
      moduleKey: row.module_key,
      version: row.version,
      overrideJson: typeof row.override_json === 'string' ? row.override_json : JSON.stringify(row.override_json),
      status: row.status,
      updatedAt: row.updated_at,
    }));
  }
}

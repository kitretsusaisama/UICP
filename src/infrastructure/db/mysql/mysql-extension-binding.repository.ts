import { Inject, Injectable } from '@nestjs/common';
import {
  ExtensionBindingRecord,
  IExtensionBindingRepository,
} from '../../../application/ports/driven/i-extension-binding.repository';
import { MYSQL_POOL, DbPool } from './mysql.module';

function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface ExtensionBindingRow {
  binding_id: Buffer;
  tenant_id: Buffer;
  module_key: string;
  extension_point: string;
  status: string;
  version: number;
  config_json: string | null;
  handler_id: Buffer;
  extension_key: string;
  kind: string;
  runtime_target: 'shared' | 'isolated';
  contract_version: string;
  handler_ref: string;
  handler_status: string;
}

@Injectable()
export class MysqlExtensionBindingRepository implements IExtensionBindingRepository {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async findActiveBinding(
    tenantId: string,
    moduleKey: string,
    extensionPoint: string,
  ): Promise<ExtensionBindingRecord | null> {
    const [rows] = await this.pool.execute<ExtensionBindingRow[]>(
      `SELECT eb.id AS binding_id,
              eb.tenant_id,
              eb.module_key,
              eb.extension_point,
              eb.status,
              eb.version,
              CAST(eb.config_json AS CHAR) AS config_json,
              eh.id AS handler_id,
              eh.extension_key,
              eh.kind,
              eh.runtime_target,
              eh.contract_version,
              eh.handler_ref,
              eh.status AS handler_status
         FROM extension_bindings eb
         JOIN extension_handlers eh
           ON eh.id = eb.handler_id
        WHERE eb.tenant_id = ?
          AND eb.module_key = ?
          AND eb.extension_point = ?
          AND eb.status = 'active'
          AND eh.status = 'active'
        LIMIT 1`,
      [uuidToBuffer(tenantId), moduleKey, extensionPoint],
    );

    const row = rows[0];
    if (!row) {
      return null;
    }

    return {
      id: bufferToUuid(row.binding_id),
      tenantId: bufferToUuid(row.tenant_id),
      moduleKey: row.module_key,
      extensionPoint: row.extension_point,
      status: row.status,
      version: row.version,
      configJson: row.config_json ?? undefined,
      handler: {
        id: bufferToUuid(row.handler_id),
        extensionKey: row.extension_key,
        kind: row.kind,
        runtimeTarget: row.runtime_target,
        contractVersion: row.contract_version,
        handlerRef: row.handler_ref,
        status: row.handler_status,
      },
    };
  }
}

import { Inject, Injectable } from '@nestjs/common';
import {
  IProviderRoutingRepository,
  ProviderRoutingRuleRecord,
} from '../../../application/ports/driven/i-provider-routing.repository';
import { MYSQL_POOL, DbPool } from './mysql.module';

function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

interface ProviderRoutingRow {
  tenant_id: Buffer | null;
  channel: 'sms' | 'email';
  purpose: string;
  country_code: string | null;
  priority: number;
  provider_key: string;
  fallback_on_error: number;
  enabled: number;
  version: number;
}

function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

@Injectable()
export class MysqlProviderRoutingRepository implements IProviderRoutingRepository {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async listRules(tenantId?: string): Promise<ProviderRoutingRuleRecord[]> {
    const params: unknown[] = [];
    let where = 'WHERE enabled = 1';
    if (tenantId) {
      where += ' AND (tenant_id = ? OR tenant_id IS NULL)';
      params.push(uuidToBuffer(tenantId));
    }

    const [rows] = await this.pool.execute<ProviderRoutingRow[]>(
      `SELECT tenant_id, channel, purpose, country_code, priority, provider_key, fallback_on_error, enabled, version
         FROM provider_routing_rules
         ${where}
        ORDER BY priority ASC`,
      params,
    );

    return rows.map((row) => ({
      tenantId: row.tenant_id ? bufferToUuid(row.tenant_id) : undefined,
      channel: row.channel.toUpperCase() as 'SMS' | 'EMAIL',
      purpose: row.purpose,
      countryCode: row.country_code ?? undefined,
      priority: row.priority,
      providerKey: row.provider_key,
      fallbackOnError: row.fallback_on_error === 1,
      enabled: row.enabled === 1,
      version: row.version,
    }));
  }
}

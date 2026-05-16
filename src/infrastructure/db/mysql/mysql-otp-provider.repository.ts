import { Inject, Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'crypto';
import {
  ITenantOtpProviderRepository,
  TenantOtpProvider,
} from '../../../application/ports/driven/i-otp-provider.repository';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { MYSQL_POOL, DbPool } from './mysql.module';
import { uuidToBuffer, bufferToUuid } from './uuid-utils';

interface TenantOtpProviderRow {
  id: Buffer;
  tenant_id: Buffer;
  provider_name: string;
  provider_type: string;
  credentials_ref: string;
  sender_id: string | null;
  template_id: string | null;
  region: string | null;
  priority: number;
  is_primary: number;
  is_enabled: number;
  circuit_state: string;
  circuit_failure_count: number;
  circuit_success_count: number;
  circuit_last_failure_at: Date | null;
  circuit_last_success_at: Date | null;
  circuit_reset_at: Date | null;
  tenant_rate_limit_per_min: number;
  tenant_daily_limit: number;
  fallback_chain: string | null;
  created_at: Date;
  updated_at: Date;
}

@Injectable()
export class MysqlOtpProviderRepository implements ITenantOtpProviderRepository {
  private readonly logger = new Logger(MysqlOtpProviderRepository.name);

  constructor(
    @Inject(MYSQL_POOL) private readonly pool: DbPool,
    @Inject(INJECTION_TOKENS.CACHE_PORT) private readonly cache: ICachePort,
  ) {}

  async findByTenantId(tenantId: string): Promise<TenantOtpProvider[]> {
    const [rows] = await this.pool.execute<TenantOtpProviderRow[]>(
      `SELECT * FROM tenant_sms_providers
       WHERE tenant_id = ? AND is_enabled = 1
       ORDER BY priority ASC`,
      [uuidToBuffer(tenantId)],
    );

    return rows.map(this.mapRowToProvider);
  }

  async findPrimaryByTenantId(tenantId: string): Promise<TenantOtpProvider | null> {
    const [rows] = await this.pool.execute<TenantOtpProviderRow[]>(
      `SELECT * FROM tenant_sms_providers
       WHERE tenant_id = ? AND is_enabled = 1 AND is_primary = 1
       LIMIT 1`,
      [uuidToBuffer(tenantId)],
    );

    if (rows.length === 0) return null;
    const row = rows[0];
    if (!row) return null;
    return this.mapRowToProvider(row);
  }

  async findByTenantAndProvider(tenantId: string, providerName: string): Promise<TenantOtpProvider | null> {
    const [rows] = await this.pool.execute<TenantOtpProviderRow[]>(
      `SELECT * FROM tenant_sms_providers
       WHERE tenant_id = ? AND provider_name = ? AND is_enabled = 1`,
      [uuidToBuffer(tenantId), providerName],
    );

    if (rows.length === 0) return null;
    const row = rows[0];
    if (!row) return null;
    return this.mapRowToProvider(row);
  }

  async create(provider: Omit<TenantOtpProvider, 'id' | 'createdAt' | 'updatedAt'>): Promise<TenantOtpProvider> {
    const id = randomUUID();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO tenant_sms_providers
       (id, tenant_id, provider_name, provider_type, credentials_ref, sender_id, template_id,
        region, priority, is_primary, is_enabled, circuit_state, circuit_failure_count,
        circuit_success_count, tenant_rate_limit_per_min, tenant_daily_limit, fallback_chain, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        uuidToBuffer(id),
        uuidToBuffer(provider.tenantId),
        provider.providerName,
        provider.providerType,
        provider.credentialsRef,
        provider.senderId,
        provider.templateId,
        provider.region,
        provider.priority,
        provider.isPrimary ? 1 : 0,
        provider.isEnabled ? 1 : 0,
        provider.circuitState,
        provider.circuitFailureCount,
        provider.circuitSuccessCount,
        provider.tenantRateLimitPerMin,
        provider.tenantDailyLimit,
        provider.fallbackChain ? JSON.stringify(provider.fallbackChain) : null,
        now,
        now,
      ],
    );

    return {
      ...provider,
      id,
      createdAt: now,
      updatedAt: now,
    };
  }

  async update(tenantId: string, providerName: string, data: Partial<TenantOtpProvider>): Promise<TenantOtpProvider> {
    const updates: string[] = [];
    const values: unknown[] = [];

    if (data.senderId !== undefined) {
      updates.push('sender_id = ?');
      values.push(data.senderId);
    }
    if (data.templateId !== undefined) {
      updates.push('template_id = ?');
      values.push(data.templateId);
    }
    if (data.isEnabled !== undefined) {
      updates.push('is_enabled = ?');
      values.push(data.isEnabled ? 1 : 0);
    }
    if (data.isPrimary !== undefined) {
      updates.push('is_primary = ?');
      values.push(data.isPrimary ? 1 : 0);
    }
    if (data.priority !== undefined) {
      updates.push('priority = ?');
      values.push(data.priority);
    }

    updates.push('updated_at = ?');
    values.push(new Date());
    values.push(uuidToBuffer(tenantId));
    values.push(providerName);

    await this.pool.execute(
      `UPDATE tenant_sms_providers SET ${updates.join(', ')} WHERE tenant_id = ? AND provider_name = ?`,
      values,
    );

    return (await this.findByTenantAndProvider(tenantId, providerName))!;
  }

  async updateCircuitState(tenantId: string, providerName: string, state: 'CLOSED' | 'OPEN' | 'HALF_OPEN'): Promise<void> {
    await this.pool.execute(
      `UPDATE tenant_sms_providers
       SET circuit_state = ?, circuit_reset_at = ?
       WHERE tenant_id = ? AND provider_name = ?`,
      [state, state === 'CLOSED' ? new Date() : null, uuidToBuffer(tenantId), providerName],
    );
  }

  async incrementFailureCount(tenantId: string, providerName: string): Promise<void> {
    await this.pool.execute(
      `UPDATE tenant_sms_providers
       SET circuit_failure_count = circuit_failure_count + 1,
           circuit_last_failure_at = NOW(),
           circuit_state = CASE
             WHEN circuit_failure_count + 1 >= 5 THEN 'OPEN'
             WHEN circuit_failure_count + 1 >= 3 THEN 'HALF_OPEN'
             ELSE circuit_state
           END
       WHERE tenant_id = ? AND provider_name = ?`,
      [uuidToBuffer(tenantId), providerName],
    );
  }

  async incrementSuccessCount(tenantId: string, providerName: string): Promise<void> {
    await this.pool.execute(
      `UPDATE tenant_sms_providers
       SET circuit_success_count = circuit_success_count + 1,
           circuit_last_success_at = NOW(),
           circuit_state = 'CLOSED',
           circuit_failure_count = 0
       WHERE tenant_id = ? AND provider_name = ?`,
      [uuidToBuffer(tenantId), providerName],
    );
  }

  async checkRateLimit(tenantId: string, providerName: string): Promise<{ current: number; limit: number }> {
    const today = new Date().toISOString().split('T')[0];
    const cacheKey = `otp:rate-limit:${tenantId}:${providerName}:${today}`;

    const currentStr = await this.cache.get(cacheKey);
    const current = currentStr ? parseInt(currentStr, 10) : 0;

    const provider = await this.findByTenantAndProvider(tenantId, providerName);
    const limit = provider?.tenantDailyLimit ?? 1000;

    return { current, limit };
  }

  async incrementRateLimit(tenantId: string, providerName: string): Promise<number> {
    const today = new Date().toISOString().split('T')[0];
    const cacheKey = `otp:rate-limit:${tenantId}:${providerName}:${today}`;

    const count = await this.cache.incr(cacheKey);
    if (count === 1) {
      const secondsUntilMidnight = this.secondsUntilMidnight();
      await this.cache.expire(cacheKey, secondsUntilMidnight);
    }

    return count;
  }

  private secondsUntilMidnight(): number {
    const now = new Date();
    const midnight = new Date(now);
    midnight.setHours(24, 0, 0, 0);
    return Math.floor((midnight.getTime() - now.getTime()) / 1000);
  }

  private mapRowToProvider(row: TenantOtpProviderRow): TenantOtpProvider {
    return {
      id: bufferToUuid(row.id),
      tenantId: bufferToUuid(row.tenant_id),
      providerName: row.provider_name,
      providerType: row.provider_type,
      credentialsRef: row.credentials_ref,
      senderId: row.sender_id ?? null,
      templateId: row.template_id ?? null,
      region: row.region ?? null,
      priority: row.priority,
      isPrimary: row.is_primary === 1,
      isEnabled: row.is_enabled === 1,
      circuitState: row.circuit_state as 'CLOSED' | 'OPEN' | 'HALF_OPEN',
      circuitFailureCount: row.circuit_failure_count,
      circuitSuccessCount: row.circuit_success_count,
      circuitLastFailureAt: row.circuit_last_failure_at,
      circuitLastSuccessAt: row.circuit_last_success_at,
      circuitResetAt: row.circuit_reset_at,
      tenantRateLimitPerMin: row.tenant_rate_limit_per_min,
      tenantDailyLimit: row.tenant_daily_limit,
      fallbackChain: row.fallback_chain ? JSON.parse(row.fallback_chain) : null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
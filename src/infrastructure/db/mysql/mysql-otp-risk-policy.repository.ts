import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import {
  ITenantOtpRiskPolicyRepository,
  TenantOtpRiskPolicy,
} from '../../../application/ports/driven/i-otp-risk.policy.port';
import { MYSQL_POOL, DbPool } from './mysql.module';
import { uuidToBuffer, bufferToUuid } from './uuid-utils';

interface TenantOtpRiskPolicyRow {
  id: Buffer;
  tenant_id: Buffer;
  max_attempts_per_hour: number;
  max_attempts_per_day: number;
  max_attempts_per_identity: number;
  allowed_countries: string;
  blocked_countries: string;
  block_unknown_geo: number;
  require_device_fingerprint: number;
  block_unknown_devices: number;
  max_devices_per_identity: number;
  trusted_providers: string;
  require_provider_verification: number;
  risk_threshold_low: number;
  risk_threshold_high: number;
  block_on_high_risk: number;
  is_active: number;
  created_at: Date;
  updated_at: Date;
}

@Injectable()
export class MysqlOtpRiskPolicyRepository implements ITenantOtpRiskPolicyRepository {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async findByTenantId(tenantId: string): Promise<TenantOtpRiskPolicy | null> {
    const [rows] = await this.pool.execute<TenantOtpRiskPolicyRow[]>(
      `SELECT * FROM tenant_otp_risk_policies WHERE tenant_id = ? AND is_active = 1`,
      [uuidToBuffer(tenantId)],
    );

    if (rows.length === 0) return null;
    const row = rows[0];
    if (!row) return null;
    return this.mapRowToPolicy(row);
  }

  async create(policy: Omit<TenantOtpRiskPolicy, 'id' | 'createdAt' | 'updatedAt'>): Promise<TenantOtpRiskPolicy> {
    const id = randomUUID();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO tenant_otp_risk_policies
       (id, tenant_id, max_attempts_per_hour, max_attempts_per_day, max_attempts_per_identity,
        allowed_countries, blocked_countries, block_unknown_geo, require_device_fingerprint,
        block_unknown_devices, max_devices_per_identity, trusted_providers, require_provider_verification,
        risk_threshold_low, risk_threshold_high, block_on_high_risk, is_active, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        uuidToBuffer(id),
        uuidToBuffer(policy.tenantId),
        policy.maxAttemptsPerHour,
        policy.maxAttemptsPerDay,
        policy.maxAttemptsPerIdentity,
        JSON.stringify(policy.allowedCountries),
        JSON.stringify(policy.blockedCountries),
        policy.blockUnknownGeo ? 1 : 0,
        policy.requireDeviceFingerprint ? 1 : 0,
        policy.blockUnknownDevices ? 1 : 0,
        policy.maxDevicesPerIdentity,
        JSON.stringify(policy.trustedProviders),
        policy.requireProviderVerification ? 1 : 0,
        policy.riskThresholdLow,
        policy.riskThresholdHigh,
        policy.blockOnHighRisk ? 1 : 0,
        policy.isActive ? 1 : 0,
        now,
        now,
      ],
    );

    return {
      ...policy,
      id,
      createdAt: now,
      updatedAt: now,
    };
  }

  async update(tenantId: string, policy: Partial<TenantOtpRiskPolicy>): Promise<TenantOtpRiskPolicy> {
    const existing = await this.findByTenantId(tenantId);
    if (!existing) {
      throw new Error(`Risk policy not found for tenant ${tenantId}`);
    }

    const updates: string[] = [];
    const values: unknown[] = [];

    if (policy.maxAttemptsPerHour !== undefined) {
      updates.push('max_attempts_per_hour = ?');
      values.push(policy.maxAttemptsPerHour);
    }
    if (policy.maxAttemptsPerDay !== undefined) {
      updates.push('max_attempts_per_day = ?');
      values.push(policy.maxAttemptsPerDay);
    }
    if (policy.allowedCountries !== undefined) {
      updates.push('allowed_countries = ?');
      values.push(JSON.stringify(policy.allowedCountries));
    }
    if (policy.blockedCountries !== undefined) {
      updates.push('blocked_countries = ?');
      values.push(JSON.stringify(policy.blockedCountries));
    }
    if (policy.blockUnknownGeo !== undefined) {
      updates.push('block_unknown_geo = ?');
      values.push(policy.blockUnknownGeo ? 1 : 0);
    }
    if (policy.trustedProviders !== undefined) {
      updates.push('trusted_providers = ?');
      values.push(JSON.stringify(policy.trustedProviders));
    }
    if (policy.riskThresholdLow !== undefined) {
      updates.push('risk_threshold_low = ?');
      values.push(policy.riskThresholdLow);
    }
    if (policy.riskThresholdHigh !== undefined) {
      updates.push('risk_threshold_high = ?');
      values.push(policy.riskThresholdHigh);
    }
    if (policy.blockOnHighRisk !== undefined) {
      updates.push('block_on_high_risk = ?');
      values.push(policy.blockOnHighRisk ? 1 : 0);
    }
    if (policy.isActive !== undefined) {
      updates.push('is_active = ?');
      values.push(policy.isActive ? 1 : 0);
    }

    updates.push('updated_at = ?');
    values.push(new Date());
    values.push(uuidToBuffer(tenantId));

    await this.pool.execute(
      `UPDATE tenant_otp_risk_policies SET ${updates.join(', ')} WHERE tenant_id = ?`,
      values,
    );

    return (await this.findByTenantId(tenantId))!;
  }

  async delete(tenantId: string): Promise<void> {
    await this.pool.execute(
      `UPDATE tenant_otp_risk_policies SET is_active = 0 WHERE tenant_id = ?`,
      [uuidToBuffer(tenantId)],
    );
  }

  private mapRowToPolicy(row: TenantOtpRiskPolicyRow): TenantOtpRiskPolicy {
    return {
      id: bufferToUuid(row.id),
      tenantId: bufferToUuid(row.tenant_id),
      maxAttemptsPerHour: row.max_attempts_per_hour,
      maxAttemptsPerDay: row.max_attempts_per_day,
      maxAttemptsPerIdentity: row.max_attempts_per_identity,
      allowedCountries: JSON.parse(row.allowed_countries || '[]'),
      blockedCountries: JSON.parse(row.blocked_countries || '[]'),
      blockUnknownGeo: row.block_unknown_geo === 1,
      requireDeviceFingerprint: row.require_device_fingerprint === 1,
      blockUnknownDevices: row.block_unknown_devices === 1,
      maxDevicesPerIdentity: row.max_devices_per_identity,
      trustedProviders: JSON.parse(row.trusted_providers || '[]'),
      requireProviderVerification: row.require_provider_verification === 1,
      riskThresholdLow: row.risk_threshold_low,
      riskThresholdHigh: row.risk_threshold_high,
      blockOnHighRisk: row.block_on_high_risk === 1,
      isActive: row.is_active === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
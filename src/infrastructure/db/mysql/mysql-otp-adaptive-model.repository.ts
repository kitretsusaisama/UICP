import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import {
  ITenantOtpAdaptiveModelRepository,
  TenantOtpAdaptiveModel,
} from '../../../application/ports/driven/i-otp-adaptive-model.port';
import { MYSQL_POOL, DbPool } from './mysql.module';
import { uuidToBuffer, bufferToUuid } from './uuid-utils';

interface TenantOtpAdaptiveModelRow {
  id: Buffer;
  tenant_id: Buffer;
  channel_success_rates: string;
  provider_success_rates: string;
  hourly_patterns: string;
  user_segment_patterns: string;
  model_version: number;
  last_trained_at: Date | null;
  training_data_points: number;
  is_active: number;
  created_at: Date;
  updated_at: Date;
}

@Injectable()
export class MysqlOtpAdaptiveModelRepository implements ITenantOtpAdaptiveModelRepository {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async findByTenantId(tenantId: string): Promise<TenantOtpAdaptiveModel | null> {
    const [rows] = await this.pool.execute<TenantOtpAdaptiveModelRow[]>(
      `SELECT * FROM tenant_otp_adaptive_models WHERE tenant_id = ? AND is_active = 1`,
      [uuidToBuffer(tenantId)],
    );

    if (rows.length === 0) return null;
    const row = rows[0];
    if (!row) return null;
    return this.mapRowToModel(row);
  }

  async create(model: Omit<TenantOtpAdaptiveModel, 'id' | 'createdAt' | 'updatedAt'>): Promise<TenantOtpAdaptiveModel> {
    const id = randomUUID();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO tenant_otp_adaptive_models
       (id, tenant_id, channel_success_rates, provider_success_rates, hourly_patterns,
        user_segment_patterns, model_version, last_trained_at, training_data_points, is_active, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        uuidToBuffer(id),
        uuidToBuffer(model.tenantId),
        JSON.stringify(model.channelSuccessRates),
        JSON.stringify(model.providerSuccessRates),
        JSON.stringify(model.hourlyPatterns),
        JSON.stringify(model.userSegmentPatterns),
        model.modelVersion,
        model.lastTrainedAt,
        model.trainingDataPoints,
        model.isActive ? 1 : 0,
        now,
        now,
      ],
    );

    return {
      ...model,
      id,
      createdAt: now,
      updatedAt: now,
    };
  }

  async update(tenantId: string, model: Partial<TenantOtpAdaptiveModel>): Promise<TenantOtpAdaptiveModel> {
    const existing = await this.findByTenantId(tenantId);
    if (!existing) {
      throw new Error(`Adaptive model not found for tenant ${tenantId}`);
    }

    const updates: string[] = [];
    const values: unknown[] = [];

    if (model.channelSuccessRates !== undefined) {
      updates.push('channel_success_rates = ?');
      values.push(JSON.stringify(model.channelSuccessRates));
    }
    if (model.providerSuccessRates !== undefined) {
      updates.push('provider_success_rates = ?');
      values.push(JSON.stringify(model.providerSuccessRates));
    }
    if (model.hourlyPatterns !== undefined) {
      updates.push('hourly_patterns = ?');
      values.push(JSON.stringify(model.hourlyPatterns));
    }
    if (model.userSegmentPatterns !== undefined) {
      updates.push('user_segment_patterns = ?');
      values.push(JSON.stringify(model.userSegmentPatterns));
    }
    if (model.modelVersion !== undefined) {
      updates.push('model_version = ?');
      values.push(model.modelVersion);
    }
    if (model.trainingDataPoints !== undefined) {
      updates.push('training_data_points = ?');
      values.push(model.trainingDataPoints);
    }

    updates.push('updated_at = ?');
    values.push(new Date());
    values.push(uuidToBuffer(tenantId));

    await this.pool.execute(
      `UPDATE tenant_otp_adaptive_models SET ${updates.join(', ')} WHERE tenant_id = ?`,
      values,
    );

    return (await this.findByTenantId(tenantId))!;
  }

  async upsert(tenantId: string, model: Partial<TenantOtpAdaptiveModel>): Promise<TenantOtpAdaptiveModel> {
    const existing = await this.findByTenantId(tenantId);

    if (existing) {
      return this.update(tenantId, model);
    }

    return this.create({
      tenantId,
      channelSuccessRates: model.channelSuccessRates ?? { SMS: 0.85, WHATSAPP: 0.95, VOICE: 0.75, EMAIL: 0.90 },
      providerSuccessRates: model.providerSuccessRates ?? { MSG91: 0.90, Twilio: 0.88 },
      hourlyPatterns: model.hourlyPatterns ?? {},
      userSegmentPatterns: model.userSegmentPatterns ?? {},
      modelVersion: model.modelVersion ?? 1,
      lastTrainedAt: model.lastTrainedAt ?? null,
      trainingDataPoints: model.trainingDataPoints ?? 0,
      isActive: true,
    });
  }

  private mapRowToModel(row: TenantOtpAdaptiveModelRow): TenantOtpAdaptiveModel {
    return {
      id: bufferToUuid(row.id),
      tenantId: bufferToUuid(row.tenant_id),
      channelSuccessRates: JSON.parse(row.channel_success_rates || '{}'),
      providerSuccessRates: JSON.parse(row.provider_success_rates || '{}'),
      hourlyPatterns: JSON.parse(row.hourly_patterns || '{}'),
      userSegmentPatterns: JSON.parse(row.user_segment_patterns || '{}'),
      modelVersion: row.model_version,
      lastTrainedAt: row.last_trained_at,
      trainingDataPoints: row.training_data_points,
      isActive: row.is_active === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
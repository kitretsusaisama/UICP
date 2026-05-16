import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import {
  ITenantOtpWidgetRepository,
  TenantOtpWidgetConfig,
} from '../../../application/ports/driven/i-otp-widget.port';
import { MYSQL_POOL, DbPool } from './mysql.module';
import { uuidToBuffer, bufferToUuid } from './uuid-utils';

interface TenantOtpWidgetRow {
  id: Buffer;
  tenant_id: Buffer;
  provider_name: string;
  widget_id: string;
  token_auth_encrypted: string;
  theme_config: string;
  layout_config: string;
  behavior_config: string;
  localization: string;
  allowed_origins: string;
  allowed_channels: string;
  ip_whitelist: string | null;
  is_active: number;
  created_at: Date;
  updated_at: Date;
}

@Injectable()
export class MysqlOtpWidgetRepository implements ITenantOtpWidgetRepository {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async findByTenantId(tenantId: string): Promise<TenantOtpWidgetConfig | null> {
    const [rows] = await this.pool.execute<TenantOtpWidgetRow[]>(
      `SELECT * FROM tenant_otp_widget_configs WHERE tenant_id = ? AND is_active = 1`,
      [uuidToBuffer(tenantId)],
    );

    if (rows.length === 0) return null;
    const row = rows[0];
    if (!row) return null;
    return this.mapRowToConfig(row);
  }

  async create(config: Omit<TenantOtpWidgetConfig, 'id' | 'createdAt' | 'updatedAt'>): Promise<TenantOtpWidgetConfig> {
    const id = randomUUID();
    const now = new Date();

    await this.pool.execute(
      `INSERT INTO tenant_otp_widget_configs
       (id, tenant_id, provider_name, widget_id, token_auth_encrypted,
        theme_config, layout_config, behavior_config, localization,
        allowed_origins, allowed_channels, ip_whitelist, is_active, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        uuidToBuffer(id),
        uuidToBuffer(config.tenantId),
        config.providerName,
        config.widgetId,
        config.tokenAuthEncrypted,
        JSON.stringify(config.themeConfig),
        JSON.stringify(config.layoutConfig),
        JSON.stringify(config.behaviorConfig),
        JSON.stringify(config.localization),
        JSON.stringify(config.allowedOrigins),
        JSON.stringify(config.allowedChannels),
        config.ipWhitelist ? JSON.stringify(config.ipWhitelist) : null,
        config.isActive ? 1 : 0,
        now,
        now,
      ],
    );

    return {
      ...config,
      id,
      createdAt: now,
      updatedAt: now,
    };
  }

  async update(tenantId: string, config: Partial<TenantOtpWidgetConfig>): Promise<TenantOtpWidgetConfig> {
    const existing = await this.findByTenantId(tenantId);
    if (!existing) {
      throw new Error(`Widget config not found for tenant ${tenantId}`);
    }

    const updates: string[] = [];
    const values: unknown[] = [];

    if (config.providerName !== undefined) {
      updates.push('provider_name = ?');
      values.push(config.providerName);
    }
    if (config.widgetId !== undefined) {
      updates.push('widget_id = ?');
      values.push(config.widgetId);
    }
    if (config.tokenAuthEncrypted !== undefined) {
      updates.push('token_auth_encrypted = ?');
      values.push(config.tokenAuthEncrypted as string);
    }
    if (config.themeConfig !== undefined) {
      updates.push('theme_config = ?');
      values.push(JSON.stringify(config.themeConfig));
    }
    if (config.layoutConfig !== undefined) {
      updates.push('layout_config = ?');
      values.push(JSON.stringify(config.layoutConfig));
    }
    if (config.behaviorConfig !== undefined) {
      updates.push('behavior_config = ?');
      values.push(JSON.stringify(config.behaviorConfig));
    }
    if (config.localization !== undefined) {
      updates.push('localization = ?');
      values.push(JSON.stringify(config.localization));
    }
    if (config.allowedOrigins !== undefined) {
      updates.push('allowed_origins = ?');
      values.push(JSON.stringify(config.allowedOrigins));
    }
    if (config.allowedChannels !== undefined) {
      updates.push('allowed_channels = ?');
      values.push(JSON.stringify(config.allowedChannels));
    }
    if (config.isActive !== undefined) {
      updates.push('is_active = ?');
      values.push(config.isActive ? 1 : 0);
    }

    updates.push('updated_at = ?');
    values.push(new Date());
    values.push(uuidToBuffer(tenantId));

    await this.pool.execute(
      `UPDATE tenant_otp_widget_configs SET ${updates.join(', ')} WHERE tenant_id = ?`,
      values,
    );

    return (await this.findByTenantId(tenantId))!;
  }

  async delete(tenantId: string): Promise<void> {
    await this.pool.execute(
      `UPDATE tenant_otp_widget_configs SET is_active = 0 WHERE tenant_id = ?`,
      [uuidToBuffer(tenantId)],
    );
  }

  private mapRowToConfig(row: TenantOtpWidgetRow): TenantOtpWidgetConfig {
    return {
      id: bufferToUuid(row.id),
      tenantId: bufferToUuid(row.tenant_id),
      providerName: row.provider_name,
      widgetId: row.widget_id,
      tokenAuthEncrypted: row.token_auth_encrypted,
      themeConfig: JSON.parse(row.theme_config || '{}'),
      layoutConfig: JSON.parse(row.layout_config || '{}'),
      behaviorConfig: JSON.parse(row.behavior_config || '{}'),
      localization: JSON.parse(row.localization || '{}'),
      allowedOrigins: JSON.parse(row.allowed_origins || '[]'),
      allowedChannels: JSON.parse(row.allowed_channels || '[]'),
      ipWhitelist: row.ip_whitelist ? JSON.parse(row.ip_whitelist) : null,
      isActive: row.is_active === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
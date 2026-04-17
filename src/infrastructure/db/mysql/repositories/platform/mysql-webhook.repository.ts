import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { IWebhookRepository } from '../../../../../domain/repositories/platform/webhook.repository.interface';
import { Webhook } from '../../../../../domain/entities/platform/webhook.entity';

@Injectable()
export class MysqlWebhookRepository implements IWebhookRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async save(webhook: Webhook): Promise<void> {
    const query = `
      INSERT INTO webhooks (id, tenant_id, app_id, url, events, secret_key, status, failure_count, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        url = VALUES(url),
        events = VALUES(events),
        status = VALUES(status),
        failure_count = VALUES(failure_count)
    `;
    await this.pool.execute(query, [
      webhook.id,
      webhook.tenantId,
      webhook.appId,
      webhook.url,
      JSON.stringify(webhook.events),
      webhook.secretKey,
      webhook.status,
      webhook.failureCount,
      webhook.createdAt,
    ]);
  }

  async findByIdAndTenant(id: string, tenantId: string): Promise<Webhook | null> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM webhooks WHERE id = ? AND tenant_id = ?',
      [id, tenantId]
    );

    if (rows.length === 0) return null;
    return this.mapToEntity(rows[0]);
  }

  async findByAppId(appId: string, tenantId: string): Promise<Webhook[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM webhooks WHERE app_id = ? AND tenant_id = ? ORDER BY created_at DESC',
      [appId, tenantId]
    );

    return rows.map((row: any) => this.mapToEntity(row));
  }

  async findByEvent(tenantId: string, eventType: string): Promise<Webhook[]> {
    // Note: JSON_CONTAINS is MySQL specific
    const [rows]: any = await this.pool.execute(
      `SELECT * FROM webhooks
       WHERE tenant_id = ?
       AND status = 'active'
       AND JSON_CONTAINS(events, ?)`,
      [tenantId, JSON.stringify(eventType)]
    );

    return rows.map((row: any) => this.mapToEntity(row));
  }

  private mapToEntity(row: any): Webhook {
    return new Webhook({
      id: row.id,
      tenantId: row.tenant_id,
      appId: row.app_id,
      url: row.url,
      events: typeof row.events === 'string' ? JSON.parse(row.events) : row.events,
      secretKey: row.secret_key,
      status: row.status,
      failureCount: row.failure_count,
      createdAt: new Date(row.created_at),
    });
  }
}

import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { IAppRepository } from '../../../../../domain/repositories/platform/app.repository.interface';
import { App } from '../../../../../domain/entities/platform/app.entity';

@Injectable()
export class MysqlAppRepository implements IAppRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async save(app: App): Promise<void> {
    const query = `
      INSERT INTO apps (id, tenant_id, client_id, name, type, redirect_uris, allowed_origins, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        name = VALUES(name),
        redirect_uris = VALUES(redirect_uris),
        allowed_origins = VALUES(allowed_origins),
        updated_at = VALUES(updated_at)
    `;
    await this.pool.execute(query, [
      app.id,
      app.tenantId,
      app.clientId,
      app.name,
      app.type,
      JSON.stringify(app.redirectUris),
      JSON.stringify(app.allowedOrigins),
      app.createdAt,
      app.updatedAt,
    ]);
  }

  async findByIdAndTenant(id: string, tenantId: string): Promise<App | null> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM apps WHERE id = ? AND tenant_id = ?',
      [id, tenantId]
    );

    if (rows.length === 0) return null;
    const row = rows[0];

    return new App({
      id: row.id,
      tenantId: row.tenant_id,
      clientId: row.client_id,
      name: row.name,
      type: row.type,
      redirectUris: typeof row.redirect_uris === 'string' ? JSON.parse(row.redirect_uris) : row.redirect_uris,
      allowedOrigins: typeof row.allowed_origins === 'string' ? JSON.parse(row.allowed_origins) : row.allowed_origins,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    });
  }

  async findByTenant(tenantId: string): Promise<App[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM apps WHERE tenant_id = ? ORDER BY created_at DESC',
      [tenantId]
    );

    return rows.map((row: any) => new App({
      id: row.id,
      tenantId: row.tenant_id,
      clientId: row.client_id,
      name: row.name,
      type: row.type,
      redirectUris: typeof row.redirect_uris === 'string' ? JSON.parse(row.redirect_uris) : row.redirect_uris,
      allowedOrigins: typeof row.allowed_origins === 'string' ? JSON.parse(row.allowed_origins) : row.allowed_origins,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    }));
  }
}

import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { IAppSecretRepository } from '../../../../../domain/repositories/platform/app-secret.repository.interface';
import { AppSecret } from '../../../../../domain/entities/platform/app-secret.entity';

@Injectable()
export class MysqlAppSecretRepository implements IAppSecretRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async save(secret: AppSecret): Promise<void> {
    const query = `
      INSERT INTO app_secrets (app_id, tenant_id, secret_hash, status, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        status = VALUES(status),
        expires_at = VALUES(expires_at)
    `;
    await this.pool.execute(query, [
      secret.appId,
      secret.tenantId,
      secret.secretHash,
      secret.status,
      secret.createdAt,
      secret.expiresAt,
    ]);
  }

  async findByAppId(appId: string, tenantId: string): Promise<AppSecret[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM app_secrets WHERE app_id = ? AND tenant_id = ? ORDER BY created_at DESC',
      [appId, tenantId]
    );

    return rows.map((row: any) => new AppSecret({
      appId: row.app_id,
      tenantId: row.tenant_id,
      secretHash: row.secret_hash,
      status: row.status,
      createdAt: new Date(row.created_at),
      expiresAt: row.expires_at ? new Date(row.expires_at) : null,
    }));
  }

  async findByHash(appId: string, tenantId: string, secretHash: string): Promise<AppSecret | null> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM app_secrets WHERE app_id = ? AND tenant_id = ? AND secret_hash = ?',
      [appId, tenantId, secretHash]
    );

    if (rows.length === 0) return null;
    const row = rows[0];

    return new AppSecret({
      appId: row.app_id,
      tenantId: row.tenant_id,
      secretHash: row.secret_hash,
      status: row.status,
      createdAt: new Date(row.created_at),
      expiresAt: row.expires_at ? new Date(row.expires_at) : null,
    });
  }
}

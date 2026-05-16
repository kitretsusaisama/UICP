import { Inject, Injectable } from '@nestjs/common';
import { Pool, RowDataPacket } from 'mysql2/promise';
import { TenantApiKey } from '../../../domain/entities/tenant-api-key.entity';
import { ITenantApiKeyRepository } from '../../../domain/repositories/tenant-api-key.repository.interface';

interface TenantApiKeyRow extends RowDataPacket {
  id: string;
  tenant_id: string;
  name: string;
  prefix: string;
  key_hash: string;
  secret_hash: string;
  scope: string;
  tier: string;
  status: string;
  ip_allowlist: string;
  rate_limit: number;
  allowed_origins: string;
  deprecated_at: Date | null;
  revoked_at: Date | null;
  expires_at: Date | null;
  last_used_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

@Injectable()
export class MySqlTenantApiKeyRepository implements ITenantApiKeyRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async save(key: TenantApiKey): Promise<void> {
    const storage = key.toStorage();
    const exists = await this.findById(key.id, key.tenantId.toString());

    if (exists) {
      await this.pool.execute(
        `UPDATE tenant_api_keys SET
          name = ?, scope = ?, tier = ?, status = ?,
          ip_allowlist = ?, rate_limit = ?, allowed_origins = ?,
          deprecated_at = ?, revoked_at = ?, expires_at = ?,
          last_used_at = ?, updated_at = NOW()
        WHERE id = ? AND tenant_id = ?`,
        [
          storage.name, storage.scope, storage.tier, storage.status,
          JSON.stringify(storage.ipAllowlist), storage.rateLimit, JSON.stringify(storage.allowedOrigins),
          storage.deprecatedAt, storage.revokedAt, storage.expiresAt,
          storage.lastUsedAt, storage.id, storage.tenantId,
        ],
      );
    } else {
      await this.pool.execute(
        `INSERT INTO tenant_api_keys (
          id, tenant_id, name, prefix, key_hash, secret_hash,
          scope, tier, status, ip_allowlist, rate_limit, allowed_origins,
          deprecated_at, revoked_at, expires_at, last_used_at,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
        [
          storage.id, storage.tenantId, storage.name, storage.prefix,
          storage.keyHash, storage.secretHash, storage.scope, storage.tier,
          storage.status, JSON.stringify(storage.ipAllowlist), storage.rateLimit,
          JSON.stringify(storage.allowedOrigins), storage.deprecatedAt,
          storage.revokedAt, storage.expiresAt, storage.lastUsedAt,
        ],
      );
    }
  }

  async findById(id: string, tenantId: string): Promise<TenantApiKey | null> {
    const [rows] = await this.pool.query<TenantApiKeyRow[]>(
      'SELECT * FROM tenant_api_keys WHERE id = ? AND tenant_id = ?',
      [id, tenantId],
    );
    return rows[0] ? TenantApiKey.fromStorage(rows[0]) : null;
  }

  async findByKeyHash(keyHash: string): Promise<TenantApiKey | null> {
    const [rows] = await this.pool.query<TenantApiKeyRow[]>(
      'SELECT * FROM tenant_api_keys WHERE key_hash = ?',
      [keyHash],
    );
    return rows[0] ? TenantApiKey.fromStorage(rows[0]) : null;
  }

  async findByTenant(tenantId: string): Promise<TenantApiKey[]> {
    const [rows] = await this.pool.query<TenantApiKeyRow[]>(
      'SELECT * FROM tenant_api_keys WHERE tenant_id = ? ORDER BY created_at DESC',
      [tenantId],
    );
    return rows.map(row => TenantApiKey.fromStorage(row));
  }

  async findActiveByTenant(tenantId: string): Promise<TenantApiKey[]> {
    const [rows] = await this.pool.query<TenantApiKeyRow[]>(
      `SELECT * FROM tenant_api_keys
       WHERE tenant_id = ? AND status = 'active'
       AND (expires_at IS NULL OR expires_at > NOW())
       ORDER BY created_at DESC`,
      [tenantId],
    );
    return rows.map(row => TenantApiKey.fromStorage(row));
  }

  async delete(id: string, tenantId: string): Promise<void> {
    await this.pool.execute(
      'DELETE FROM tenant_api_keys WHERE id = ? AND tenant_id = ?',
      [id, tenantId],
    );
  }

  async updateLastUsed(id: string, tenantId: string): Promise<void> {
    await this.pool.execute(
      'UPDATE tenant_api_keys SET last_used_at = NOW() WHERE id = ? AND tenant_id = ?',
      [id, tenantId],
    );
  }
}
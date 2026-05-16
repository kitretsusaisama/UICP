import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { IPlatformApiKeyRepository } from '../../../../../domain/repositories/platform/platform-api-key.repository.interface';
import { PlatformApiKeyEntity } from '../../../../../domain/entities/platform/platform-api-key.entity';
import { ApiKeyType, ApiKeyEnv } from '../../../../../domain/entities/api-key.entity';

interface PlatformApiKeyRow {
  id: string;
  ulid: string;
  platform_identity_id: string;
  type: string;
  env: string;
  scopes: string;
  ip_allowlist: string;
  rate_limit: number;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  last_used_at: Date | null;
  last_used_ip: string | null;
  metadata: string;
  secret_hash: string | null;
}

@Injectable()
export class MysqlPlatformApiKeyRepository implements IPlatformApiKeyRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async findByUlid(ulid: string): Promise<PlatformApiKeyEntity | null> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM platform_api_keys WHERE ulid = ?',
      [ulid]
    );
    if (rows.length === 0) return null;
    return this.rowToEntity(rows[0]);
  }

  async findById(id: string): Promise<PlatformApiKeyEntity | null> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM platform_api_keys WHERE id = ?',
      [id]
    );
    if (rows.length === 0) return null;
    return this.rowToEntity(rows[0]);
  }

  async findByPlatformIdentityId(platformIdentityId: string): Promise<PlatformApiKeyEntity[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM platform_api_keys WHERE platform_identity_id = ? ORDER BY created_at DESC',
      [platformIdentityId]
    );
    return rows.map((row: any) => this.rowToEntity(row));
  }

  async findAll(): Promise<PlatformApiKeyEntity[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM platform_api_keys ORDER BY created_at DESC'
    );
    return rows.map((row: any) => this.rowToEntity(row));
  }

  async save(entity: PlatformApiKeyEntity): Promise<PlatformApiKeyEntity> {
    const query = `
      INSERT INTO platform_api_keys (
        id, ulid, platform_identity_id, type, env, scopes, ip_allowlist,
        rate_limit, created_at, expires_at, revoked_at, last_used_at,
        last_used_ip, metadata, secret_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        scopes = VALUES(scopes),
        ip_allowlist = VALUES(ip_allowlist),
        rate_limit = VALUES(rate_limit),
        revoked_at = VALUES(revoked_at),
        last_used_at = VALUES(last_used_at),
        last_used_ip = VALUES(last_used_ip),
        metadata = VALUES(metadata)
    `;

    await this.pool.execute(query, [
      entity.id, entity.ulid, entity.platformIdentityId, entity.type, entity.env,
      JSON.stringify(entity.scopes), JSON.stringify(entity.ipAllowlist),
      entity.rateLimit, entity.createdAt, entity.expiresAt,
      entity.isRevoked ? (entity as any).props.revokedAt : null,
      entity.lastUsedAt, entity.lastUsedIp, JSON.stringify(entity.metadata),
      (entity as any).props.secretHash,
    ]);
    return entity;
  }

  async delete(id: string): Promise<void> {
    await this.pool.execute('DELETE FROM platform_api_keys WHERE id = ?', [id]);
  }

  private rowToEntity(row: PlatformApiKeyRow): PlatformApiKeyEntity {
    return new PlatformApiKeyEntity({
      id: row.id, ulid: row.ulid, platformIdentityId: row.platform_identity_id,
      type: row.type as ApiKeyType, env: row.env as ApiKeyEnv,
      scopes: JSON.parse(row.scopes), ipAllowlist: JSON.parse(row.ip_allowlist),
      rateLimit: row.rate_limit, createdAt: new Date(row.created_at),
      expiresAt: new Date(row.expires_at), revokedAt: row.revoked_at ?? undefined,
      lastUsedAt: row.last_used_at ?? undefined, lastUsedIp: row.last_used_ip ?? undefined,
      metadata: JSON.parse(row.metadata), secretHash: row.secret_hash ?? undefined,
    });
  }
}
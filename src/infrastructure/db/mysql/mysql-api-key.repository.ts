import { Inject, Injectable } from '@nestjs/common';
import { IApiKeyRepository } from '../../../domain/repositories/api-key.repository.interface';
import { ApiKeyEntity, ApiKeyType, ApiKeyEnv, ApiKeyScope, ApiKeyProps } from '../../../domain/entities/api-key.entity';
import { MYSQL_POOL, DbPool } from './mysql.module';
import { uuidToBuffer, bufferToUuid } from './uuid-utils';

interface ApiKeyRow {
  id: Buffer;
  ulid: string;
  tenant_id: Buffer;
  type: string;
  env: string;
  scopes: string;
  ip_allowlist: string;
  domain_allowlist: string;
  allowed_origins: string;
  rate_limit: number;
  monthly_quota: number | null;
  quota_used: number | null;
  created_at: Date;
  expires_at: Date;
  last_used_at: Date | null;
  last_used_ip: string | null;
  last_used_user_agent: string | null;
  revoked_at: Date | null;
  revoked_by: Buffer | null;
  revocation_reason: string | null;
  metadata: string;
  secret_hash: string | null;
  project_id: string | null;
  service_account_id: string | null;
  tags: string;
  rotation_scheduled_at: Date | null;
  rotated_at: Date | null;
  rotation_frequency_days: number | null;
  previous_key_id: string | null;
}

@Injectable()
export class MySqlApiKeyRepository implements IApiKeyRepository {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async findByUlid(ulid: string): Promise<ApiKeyEntity | null> {
    const [rows] = await this.pool.execute<ApiKeyRow[]>(
      `SELECT * FROM api_keys WHERE ulid = ? LIMIT 1`,
      [ulid],
    );
    const row = rows[0];
    return row ? this.rowToEntity(row) : null;
  }

  async findByTenantId(tenantId: string): Promise<ApiKeyEntity[]> {
    const [rows] = await this.pool.execute<ApiKeyRow[]>(
      `SELECT * FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC`,
      [uuidToBuffer(tenantId)],
    );
    return rows.map(row => this.rowToEntity(row));
  }

  async findById(id: string): Promise<ApiKeyEntity | null> {
    const [rows] = await this.pool.execute<ApiKeyRow[]>(
      `SELECT * FROM api_keys WHERE id = ? LIMIT 1`,
      [uuidToBuffer(id)],
    );
    const row = rows[0];
    return row ? this.rowToEntity(row) : null;
  }

  async save(entity: ApiKeyEntity): Promise<ApiKeyEntity> {
    const props = (entity as unknown as { props: ApiKeyProps }).props || entity;

    await this.pool.execute(
      `INSERT INTO api_keys (
        id, ulid, tenant_id, type, env, scopes, ip_allowlist, domain_allowlist,
        allowed_origins, rate_limit, monthly_quota, quota_used, created_at,
        expires_at, last_used_at, last_used_ip, last_used_user_agent,
        revoked_at, revoked_by, revocation_reason, metadata, secret_hash,
        project_id, service_account_id, tags, rotation_scheduled_at,
        rotated_at, rotation_frequency_days, previous_key_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        type = VALUES(type), env = VALUES(env), scopes = VALUES(scopes),
        ip_allowlist = VALUES(ip_allowlist), domain_allowlist = VALUES(domain_allowlist),
        allowed_origins = VALUES(allowed_origins), rate_limit = VALUES(rate_limit),
        monthly_quota = VALUES(monthly_quota), quota_used = VALUES(quota_used),
        last_used_at = VALUES(last_used_at), last_used_ip = VALUES(last_used_ip),
        last_used_user_agent = VALUES(last_used_user_agent),
        revoked_at = VALUES(revoked_at), revoked_by = VALUES(revoked_by),
        revocation_reason = VALUES(revocation_reason), metadata = VALUES(metadata),
        rotation_scheduled_at = VALUES(rotation_scheduled_at),
        rotated_at = VALUES(rotated_at), previous_key_id = VALUES(previous_key_id)`,
      [
        uuidToBuffer(props.id),
        props.ulid,
        uuidToBuffer(props.tenantId),
        props.type,
        props.env,
        JSON.stringify(props.scopes),
        JSON.stringify(props.ipAllowlist),
        JSON.stringify(props.domainAllowlist),
        JSON.stringify(props.allowedOrigins),
        props.rateLimit,
        props.monthlyQuota ?? null,
        props.quotaUsed ?? null,
        props.createdAt,
        props.expiresAt,
        props.lastUsedAt ?? null,
        props.lastUsedIp ?? null,
        props.lastUsedUserAgent ?? null,
        props.revokedAt ?? null,
        props.revokedBy ? uuidToBuffer(props.revokedBy) : null,
        props.revocationReason ?? null,
        JSON.stringify(props.metadata),
        props.secretHash ?? null,
        props.projectId ?? null,
        props.serviceAccountId ?? null,
        JSON.stringify(props.tags),
        props.rotationScheduledAt ?? null,
        props.rotatedAt ?? null,
        props.rotationFrequencyDays ?? null,
        props.previousKeyId ?? null,
      ],
    );
    return entity;
  }

  async delete(id: string): Promise<void> {
    await this.pool.execute(
      `UPDATE api_keys SET revoked_at = NOW() WHERE id = ?`,
      [uuidToBuffer(id)],
    );
  }

  private rowToEntity(row: ApiKeyRow): ApiKeyEntity {
    const props: ApiKeyProps = {
      id: bufferToUuid(row.id),
      ulid: row.ulid,
      tenantId: bufferToUuid(row.tenant_id),
      type: row.type as ApiKeyType,
      env: row.env as ApiKeyEnv,
      scopes: JSON.parse(row.scopes || '[]') as ApiKeyScope[],
      ipAllowlist: JSON.parse(row.ip_allowlist || '[]') as string[],
      domainAllowlist: JSON.parse(row.domain_allowlist || '[]') as string[],
      allowedOrigins: JSON.parse(row.allowed_origins || '[]') as string[],
      rateLimit: row.rate_limit,
      monthlyQuota: row.monthly_quota ?? undefined,
      quotaUsed: row.quota_used ?? undefined,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      lastUsedAt: row.last_used_at ?? undefined,
      lastUsedIp: row.last_used_ip ?? undefined,
      lastUsedUserAgent: row.last_used_user_agent ?? undefined,
      revokedAt: row.revoked_at ?? undefined,
      revokedBy: row.revoked_by ? bufferToUuid(row.revoked_by) : undefined,
      revocationReason: row.revocation_reason ?? undefined,
      metadata: JSON.parse(row.metadata || '{}'),
      secretHash: row.secret_hash ?? undefined,
      projectId: row.project_id ?? undefined,
      serviceAccountId: row.service_account_id ?? undefined,
      tags: JSON.parse(row.tags || '[]') as string[],
      rotationScheduledAt: row.rotation_scheduled_at ?? undefined,
      rotatedAt: row.rotated_at ?? undefined,
      rotationFrequencyDays: row.rotation_frequency_days ?? undefined,
      previousKeyId: row.previous_key_id ?? undefined,
    };
    return new ApiKeyEntity(props);
  }
}
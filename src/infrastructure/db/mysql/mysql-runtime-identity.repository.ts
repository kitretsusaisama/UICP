import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import {
  EnsurePrincipalGraphInput,
  IRuntimeIdentityRepository,
  RuntimeActorSummary,
  RuntimeAuthMethodSummary,
  RuntimeIdentityContext,
  RuntimeMembershipSummary,
} from '../../../application/ports/driven/i-runtime-identity.repository';
import { MYSQL_POOL, DbPool } from './mysql.module';

function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

type PrincipalStatus = 'pending' | 'active' | 'suspended' | 'deleted';

interface RuntimeContextRow {
  principal_id: Buffer;
  principal_status: PrincipalStatus;
  tenant_id: Buffer;
  membership_id: Buffer;
  membership_status: string;
  tenant_type: string | null;
  isolation_tier: string | null;
  runtime_status: string | null;
  actor_id: Buffer;
  actor_type: string;
  actor_status: string;
  display_name_enc: Buffer | null;
}

interface MembershipRow {
  id: Buffer;
  tenant_id: Buffer;
  principal_id: Buffer;
  status: string;
  tenant_type: string | null;
  isolation_tier: string | null;
  runtime_status: string | null;
}

interface ActorRow {
  id: Buffer;
  membership_id: Buffer;
  actor_type: string;
  status: string;
  is_default: number;
  display_name_enc: Buffer | null;
}

interface AuthMethodRow {
  id: Buffer;
  type: string;
  verified: number;
  provider_name: string | null;
  provider_subject: string | null;
}

@Injectable()
export class MysqlRuntimeIdentityRepository implements IRuntimeIdentityRepository {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async ensurePrincipalGraph(input: EnsurePrincipalGraphInput): Promise<RuntimeIdentityContext> {
    const principalId = input.principalId;
    const tenantId = input.tenantId;
    const normalizedStatus = this.mapPrincipalStatus(input.principalStatus);

    const conn = await this.pool.getConnection();
    try {
      await conn.beginTransaction();

      await conn.execute(
        `INSERT INTO global_principals (id, status, created_at, updated_at)
         VALUES (?, ?, NOW(3), NOW(3))
         ON DUPLICATE KEY UPDATE status = VALUES(status), updated_at = NOW(3)`,
        [uuidToBuffer(principalId), normalizedStatus],
      );

      for (const method of input.authMethods) {
        const hash = Buffer.from(method.valueHash, 'hex');
        await conn.execute(
          `INSERT INTO principal_auth_methods
             (id, principal_id, type, normalized_value_enc, normalized_value_enc_kid, normalized_value_hash,
              provider_subject, provider_name, verified, verified_at, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(3), NOW(3))
           ON DUPLICATE KEY UPDATE
             principal_id = VALUES(principal_id),
             provider_subject = VALUES(provider_subject),
             provider_name = VALUES(provider_name),
             verified = GREATEST(verified, VALUES(verified)),
             verified_at = COALESCE(principal_auth_methods.verified_at, VALUES(verified_at)),
             updated_at = NOW(3)`,
          [
            uuidToBuffer(method.id),
            uuidToBuffer(principalId),
            this.mapAuthMethodType(method.type),
            Buffer.from(method.type),
            'legacy-bridge',
            hash,
            method.providerSubject ?? null,
            method.providerName ?? null,
            method.verified ? 1 : 0,
            method.verifiedAt ?? null,
          ],
        );
      }

      const membershipId = await this.ensureMembership(conn, tenantId, principalId);
      await this.ensureRuntimeSettings(conn, tenantId);
      const actorId = await this.ensureDefaultActor(conn, membershipId, input.preferredActorType ?? 'member');

      await conn.commit();

      return this.findContext(principalId, tenantId, actorId) as Promise<RuntimeIdentityContext>;
    } catch (error) {
      await conn.rollback();
      throw error;
    } finally {
      conn.release();
    }
  }

  async findContext(principalId: string, tenantId: string, actorId?: string): Promise<RuntimeIdentityContext | null> {
    const params: unknown[] = [uuidToBuffer(principalId), uuidToBuffer(tenantId)];
    let actorWhere = 'AND ap.is_default = 1';
    if (actorId) {
      actorWhere = 'AND ap.id = ?';
      params.push(uuidToBuffer(actorId));
    }

    const [rows] = await this.pool.execute<RuntimeContextRow[]>(
      `SELECT gp.id AS principal_id,
              gp.status AS principal_status,
              tm.tenant_id,
              tm.id AS membership_id,
              tm.status AS membership_status,
              trs.tenant_type,
              trs.isolation_tier,
              trs.runtime_status,
              ap.id AS actor_id,
              ap.actor_type,
              ap.status AS actor_status,
              ap.display_name_enc
         FROM global_principals gp
         JOIN tenant_memberships tm
           ON tm.principal_id = gp.id
         LEFT JOIN tenant_runtime_settings trs
           ON trs.tenant_id = tm.tenant_id
         JOIN actor_profiles ap
           ON ap.membership_id = tm.id
        WHERE gp.id = ?
          AND tm.tenant_id = ?
          ${actorWhere}
        ORDER BY ap.is_default DESC, ap.created_at ASC
        LIMIT 1`,
      params,
    );

    const row = rows[0];
    if (!row) {
      return null;
    }

    const authMethodsSummary = await this.listAuthMethods(principalId);

    return {
      principalId: bufferToUuid(row.principal_id),
      principalStatus: row.principal_status,
      tenantId: bufferToUuid(row.tenant_id),
      membershipId: bufferToUuid(row.membership_id),
      membershipStatus: row.membership_status,
      tenantType: row.tenant_type ?? 'workspace',
      isolationTier: row.isolation_tier ?? 'shared',
      runtimeStatus: row.runtime_status ?? 'active',
      actorId: bufferToUuid(row.actor_id),
      actorType: row.actor_type,
      actorStatus: row.actor_status,
      actorDisplayName: row.display_name_enc ? row.display_name_enc.toString('utf8') : undefined,
      authMethodsSummary,
    };
  }

  async listMemberships(principalId: string): Promise<RuntimeMembershipSummary[]> {
    const [rows] = await this.pool.execute<MembershipRow[]>(
      `SELECT tm.id, tm.tenant_id, tm.principal_id, tm.status,
              trs.tenant_type, trs.isolation_tier, trs.runtime_status
         FROM tenant_memberships tm
         LEFT JOIN tenant_runtime_settings trs
           ON trs.tenant_id = tm.tenant_id
        WHERE tm.principal_id = ?
        ORDER BY tm.created_at ASC`,
      [uuidToBuffer(principalId)],
    );

    return rows.map((row) => ({
      id: bufferToUuid(row.id),
      tenantId: bufferToUuid(row.tenant_id),
      principalId: bufferToUuid(row.principal_id),
      status: row.status,
      tenantType: row.tenant_type ?? 'workspace',
      isolationTier: row.isolation_tier ?? 'shared',
      runtimeStatus: row.runtime_status ?? 'active',
    }));
  }

  async listActors(membershipId: string): Promise<RuntimeActorSummary[]> {
    const [rows] = await this.pool.execute<ActorRow[]>(
      `SELECT id, membership_id, actor_type, status, is_default, display_name_enc
         FROM actor_profiles
        WHERE membership_id = ?
        ORDER BY is_default DESC, created_at ASC`,
      [uuidToBuffer(membershipId)],
    );

    return rows.map((row) => ({
      id: bufferToUuid(row.id),
      membershipId: bufferToUuid(row.membership_id),
      actorType: row.actor_type,
      status: row.status,
      isDefault: row.is_default === 1,
      displayName: row.display_name_enc ? row.display_name_enc.toString('utf8') : undefined,
    }));
  }

  async findActor(membershipId: string, actorId: string): Promise<RuntimeActorSummary | null> {
    const [rows] = await this.pool.execute<ActorRow[]>(
      `SELECT id, membership_id, actor_type, status, is_default, display_name_enc
         FROM actor_profiles
        WHERE membership_id = ?
          AND id = ?
        LIMIT 1`,
      [uuidToBuffer(membershipId), uuidToBuffer(actorId)],
    );

    const row = rows[0];
    if (!row) {
      return null;
    }

    return {
      id: bufferToUuid(row.id),
      membershipId: bufferToUuid(row.membership_id),
      actorType: row.actor_type,
      status: row.status,
      isDefault: row.is_default === 1,
      displayName: row.display_name_enc ? row.display_name_enc.toString('utf8') : undefined,
    };
  }

  async listAuthMethods(principalId: string): Promise<RuntimeAuthMethodSummary[]> {
    const [rows] = await this.pool.execute<AuthMethodRow[]>(
      `SELECT id, type, verified, provider_name, provider_subject
         FROM principal_auth_methods
        WHERE principal_id = ?
        ORDER BY created_at ASC`,
      [uuidToBuffer(principalId)],
    );

    return rows.map((row) => ({
      id: bufferToUuid(row.id),
      type: row.type,
      verified: row.verified === 1,
      providerName: row.provider_name ?? undefined,
      providerSubject: row.provider_subject ?? undefined,
    }));
  }

  private async ensureMembership(conn: any, tenantId: string, principalId: string): Promise<string> {
    const [rows] = await conn.execute(
      `SELECT id FROM tenant_memberships WHERE tenant_id = ? AND principal_id = ? LIMIT 1`,
      [uuidToBuffer(tenantId), uuidToBuffer(principalId)],
    );

    const existing = (rows as Array<{ id: Buffer }>)[0];
    if (existing) {
      return bufferToUuid(existing.id);
    }

    const membershipId = randomUUID();
    await conn.execute(
      `INSERT INTO tenant_memberships
         (id, tenant_id, principal_id, status, joined_at, created_at, updated_at)
       VALUES (?, ?, ?, 'active', NOW(3), NOW(3), NOW(3))`,
      [uuidToBuffer(membershipId), uuidToBuffer(tenantId), uuidToBuffer(principalId)],
    );
    return membershipId;
  }

  private async ensureDefaultActor(conn: any, membershipId: string, actorType: string): Promise<string> {
    const [rows] = await conn.execute(
      `SELECT id
         FROM actor_profiles
        WHERE membership_id = ?
        ORDER BY is_default DESC, created_at ASC
        LIMIT 1`,
      [uuidToBuffer(membershipId)],
    );

    const existing = (rows as Array<{ id: Buffer }>)[0];
    if (existing) {
      return bufferToUuid(existing.id);
    }

    const actorId = randomUUID();
    await conn.execute(
      `INSERT INTO actor_profiles
         (id, membership_id, actor_type, status, is_default, display_name_enc, created_at, updated_at)
       VALUES (?, ?, ?, 'active', 1, ?, NOW(3), NOW(3))`,
      [uuidToBuffer(actorId), uuidToBuffer(membershipId), actorType, Buffer.from(actorType)],
    );
    return actorId;
  }

  private async ensureRuntimeSettings(conn: any, tenantId: string): Promise<void> {
    const [rows] = await conn.execute(
      `SELECT id FROM tenant_runtime_settings WHERE tenant_id = ? LIMIT 1`,
      [uuidToBuffer(tenantId)],
    );

    if ((rows as Array<{ id: Buffer }>)[0]) {
      return;
    }

    await conn.execute(
      `INSERT INTO tenant_runtime_settings
         (id, tenant_id, tenant_type, isolation_tier, runtime_status, settings_json, created_at, updated_at)
       VALUES (?, ?, 'workspace', 'shared', 'active', JSON_OBJECT(), NOW(3), NOW(3))`,
      [uuidToBuffer(randomUUID()), uuidToBuffer(tenantId)],
    );
  }

  private mapPrincipalStatus(status: string): PrincipalStatus {
    switch (status.toUpperCase()) {
      case 'ACTIVE':
        return 'active';
      case 'SUSPENDED':
        return 'suspended';
      case 'DELETED':
        return 'deleted';
      default:
        return 'pending';
    }
  }

  private mapAuthMethodType(type: string): string {
    const normalized = type.toLowerCase();
    switch (normalized) {
      case 'oauth_google':
      case 'google':
        return 'google';
      case 'oauth_github':
      case 'github':
        return 'github';
      case 'oauth_apple':
      case 'apple':
        return 'apple';
      case 'oauth_microsoft':
      case 'microsoft':
        return 'microsoft';
      case 'phone':
        return 'phone';
      default:
        return 'email';
    }
  }
}

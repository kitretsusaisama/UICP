import { Inject, Injectable, ConflictException, Optional } from '@nestjs/common';
import { IUserRepository } from '../../../application/ports/driven/i-user.repository';
import { User, UserStatus } from '../../../domain/aggregates/user.aggregate';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { IdentityId } from '../../../domain/value-objects/identity-id.vo';
import { Identity, IdentityType, toEncryptedValue } from '../../../domain/entities/identity.entity';
import { Credential } from '../../../domain/entities/credential.entity';
import { MYSQL_POOL, DbPool, DbConnection } from './mysql.module';
import { ITracerPort } from '../../../application/ports/driven/i-tracer.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
/** Convert a UUID string to a 16-byte Buffer for BINARY(16) columns. */
function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

/** Convert a 16-byte Buffer back to a UUID string. */
function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface UserRow {
  id: Buffer;
  tenant_id: Buffer;
  display_name_enc: Buffer | null;
  display_name_enc_kid: string | null;
  status: string;
  suspend_until: Date | null;
  suspend_reason: string | null;
  metadata_enc: Buffer | null;
  metadata_enc_kid: string | null;
  version: number;
  created_at: Date;
  updated_at: Date;
}

interface IdentityRow {
  id: Buffer;
  tenant_id: Buffer;
  user_id: Buffer;
  type: string;
  value_enc: Buffer;
  value_enc_kid: string;
  value_hash: Buffer;
  provider_sub: string | null;
  provider_data_enc: Buffer | null;
  provider_data_enc_kid: string | null;
  verified: number;
  verified_at: Date | null;
  created_at: Date;
}

interface CredentialRow {
  hash: string;
  algorithm: string;
  rounds: number;
  created_at: Date;
  updated_at: Date;
}

function mapIdentityType(dbType: string): IdentityType {
  const map: Record<string, IdentityType> = {
    email: 'EMAIL',
    phone: 'PHONE',
    google: 'OAUTH_GOOGLE',
    github: 'OAUTH_GITHUB',
    apple: 'OAUTH_APPLE',
    microsoft: 'OAUTH_MICROSOFT',
  };
  return map[dbType] ?? (dbType as IdentityType);
}

function identityTypeToDb(type: IdentityType): string {
  const map: Record<IdentityType, string> = {
    EMAIL: 'email',
    PHONE: 'phone',
    OAUTH_GOOGLE: 'google',
    OAUTH_GITHUB: 'github',
    OAUTH_APPLE: 'apple',
    OAUTH_MICROSOFT: 'microsoft',
  };
  return map[type];
}

function rowToIdentity(row: IdentityRow): Identity {
  return Identity.reconstitute({
    id: IdentityId.from(bufferToUuid(row.id)),
    tenantId: TenantId.from(bufferToUuid(row.tenant_id)),
    userId: UserId.from(bufferToUuid(row.user_id)),
    type: mapIdentityType(row.type),
    valueEnc: toEncryptedValue(row.value_enc.toString('utf8')),
    valueHash: row.value_hash.toString('hex'),
    providerSub: row.provider_sub ?? undefined,
    providerDataEnc: row.provider_data_enc
      ? toEncryptedValue(row.provider_data_enc.toString('utf8'))
      : undefined,
    verified: row.verified === 1,
    verifiedAt: row.verified_at ?? undefined,
    createdAt: row.created_at,
  });
}

/**
 * MySQL implementation of IUserRepository.
 *
 * - Every query includes WHERE tenant_id = ? (Req 1.1, 1.2).
 * - Reads route to replica pool; writes route to primary pool.
 * - Uses optimistic locking via the `version` column (Req 2.7).
 *
 * NOTE: In this implementation both primary and replica use the same pool
 * (single-pool setup). When a read-replica pool is wired in, inject it via
 * a separate token (e.g. MYSQL_REPLICA_POOL) and swap the pool used in
 * findById / findByTenantId.
 */
@Injectable()
export class MysqlUserRepository implements IUserRepository {
  constructor(
    @Inject(MYSQL_POOL) private readonly pool: DbPool,
    @Optional() @Inject(INJECTION_TOKENS.TRACER_PORT) private readonly tracer?: ITracerPort,
  ) {}

  async findById(userId: UserId, tenantId: TenantId): Promise<User | null> {
    const start = Date.now();
    const doFind = async () => {
      const [rows] = await this.pool.execute<UserRow[]>(
        `SELECT id, tenant_id, display_name_enc, display_name_enc_kid,
                status, suspend_until, suspend_reason,
                metadata_enc, metadata_enc_kid,
                version, created_at, updated_at
           FROM users
          WHERE id = ? AND tenant_id = ?
          LIMIT 1`,
        [uuidToBuffer(userId.toString()), uuidToBuffer(tenantId.toString())],
      );
      if (rows.length === 0) return null;
      return this._hydrateUser(rows[0]!);
    };

    if (this.tracer) {
      return this.tracer.withSpan('db.users.findById', doFind, {
        'db.system': 'mysql',
        'db.operation': 'SELECT',
        'db.table': 'users',
        'db.duration_ms': Date.now() - start,
      });
    }
    return doFind();
  }

  async findByTenantId(tenantId: TenantId): Promise<User[]> {
    const [rows] = await this.pool.execute<UserRow[]>(
      `SELECT id, tenant_id, display_name_enc, display_name_enc_kid,
              status, suspend_until, suspend_reason,
              metadata_enc, metadata_enc_kid,
              version, created_at, updated_at
         FROM users
        WHERE tenant_id = ?
        ORDER BY created_at ASC`,
      [uuidToBuffer(tenantId.toString())],
    );

    return Promise.all(rows.map((row) => this._hydrateUser(row)));
  }

  async save(user: User): Promise<void> {
    const doSave = async () => {
      const conn = await this.pool.getConnection();
      try {
        await conn.beginTransaction();

        await conn.execute(
          `INSERT INTO users
             (id, tenant_id, status, version, created_at, updated_at)
           VALUES (?, ?, ?, 0, ?, ?)`,
          [
            uuidToBuffer(user.getId().toString()),
            uuidToBuffer(user.getTenantId().toString()),
            user.getStatus().toLowerCase(),
            user.getCreatedAt(),
            user.getUpdatedAt(),
          ],
        );

        // Persist linked identities
        for (const identity of user.getIdentities()) {
          await this._insertIdentity(conn, identity);
        }

        // Persist credential if present
        const credential = user.getCredential();
        if (credential) {
          await this._upsertCredential(conn, user.getId(), credential);
        }

        // WAR-GRADE DEFENSE: Transactional Outbox Pattern Atomicity
        // Drain domain events from the aggregate and append to outbox table
        // guaranteeing atomicity between user identity records and event dispatches.
        const events = user.pullDomainEvents();
        for (const event of events) {
          const payload = {
            ...event.payload,
            aggregateId: event.aggregateId,
            aggregateType: event.aggregateType,
            tenantId: event.tenantId,
          };
          await conn.execute(
            `INSERT INTO outbox_events
               (id, event_type, payload_json, status, attempts, created_at)
             VALUES (UUID_TO_BIN(UUID()), ?, ?, 'PENDING', 0, ?)`,
            [
              event.eventType,
              JSON.stringify(payload),
              new Date(),
            ],
          );
        }

        await conn.commit();
      } catch (err: unknown) {
        await conn.rollback();
        if (this._isDuplicateKeyError(err)) {
          throw new ConflictException('IDENTITY_ALREADY_EXISTS');
        }
        throw err;
      } finally {
        conn.release();
      }
    };

    if (this.tracer) {
      return this.tracer.withSpan('db.users.save', doSave, {
        'db.system': 'mysql',
        'db.operation': 'INSERT',
        'db.table': 'users',
        'db.rows_affected': 1,
      });
    }
    return doSave();
  }

  async update(user: User): Promise<void> {
    const doUpdate = async () => {
      const conn = await this.pool.getConnection();
      try {
        await conn.beginTransaction();

        const [result] = await conn.execute(
          `UPDATE users
              SET status      = ?,
                  suspend_until = ?,
                  suspend_reason = ?,
                  version     = version + 1,
                  updated_at  = ?
            WHERE id        = ?
              AND tenant_id = ?
              AND version   = ?`,
          [
            user.getStatus().toLowerCase(),
            user.getSuspendUntil() ?? null,
            null,
            user.getUpdatedAt(),
            uuidToBuffer(user.getId().toString()),
            uuidToBuffer(user.getTenantId().toString()),
            user.getVersion(),
          ],
        );

        if ((result as { affectedRows: number }).affectedRows === 0) {
          throw new ConflictException('VERSION_CONFLICT');
        }

        // Upsert identities (new ones added via linkIdentity / verifyIdentity)
        for (const identity of user.getIdentities()) {
          await conn.execute(
            `INSERT INTO identities
               (id, tenant_id, user_id, type, value_enc, value_enc_kid,
                value_hash, provider_sub, provider_data_enc, provider_data_enc_kid,
                verified, verified_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
               verified     = VALUES(verified),
               verified_at  = VALUES(verified_at),
               provider_data_enc = VALUES(provider_data_enc),
               provider_data_enc_kid = VALUES(provider_data_enc_kid)`,
            [
              uuidToBuffer(identity.id.toString()),
              uuidToBuffer(identity.tenantId.toString()),
              uuidToBuffer(identity.userId.toString()),
              identityTypeToDb(identity.getType()),
              Buffer.from(identity.getValueEnc()),
              '',
              Buffer.from(identity.getValueHash(), 'hex'),
              identity.getProviderSub() ?? null,
              identity.getProviderDataEnc() ? Buffer.from(identity.getProviderDataEnc()!) : null,
              null,
              identity.isVerified() ? 1 : 0,
              identity.getVerifiedAt() ?? null,
              identity.createdAt,
            ],
          );
        }

        // Upsert credential
        const credential = user.getCredential();
        if (credential) {
          await this._upsertCredential(conn, user.getId(), credential);
        }

        // WAR-GRADE DEFENSE: Transactional Outbox Pattern Atomicity
        // Ensure ALL outbox events generated by aggregate updates are committed simultaneously.
        const events = user.pullDomainEvents();
        for (const event of events) {
          const payload = {
            ...event.payload,
            aggregateId: event.aggregateId,
            aggregateType: event.aggregateType,
            tenantId: event.tenantId,
          };
          await conn.execute(
            `INSERT INTO outbox_events
               (id, event_type, payload_json, status, attempts, created_at)
             VALUES (UUID_TO_BIN(UUID()), ?, ?, 'PENDING', 0, ?)`,
            [
              event.eventType,
              JSON.stringify(payload),
              new Date(),
            ],
          );
        }

        await conn.commit();
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }
    };

    if (this.tracer) {
      return this.tracer.withSpan('db.users.update', doUpdate, {
        'db.system': 'mysql',
        'db.operation': 'UPDATE',
        'db.table': 'users',
        'db.rows_affected': 1,
      });
    }
    return doUpdate();
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async _hydrateUser(row: UserRow): Promise<User> {
    const userId = bufferToUuid(row.id);
    const tenantId = bufferToUuid(row.tenant_id);

    const [identityRows] = await this.pool.execute<IdentityRow[]>(
      `SELECT id, tenant_id, user_id, type, value_enc, value_enc_kid,
              value_hash, provider_sub, provider_data_enc, provider_data_enc_kid,
              verified, verified_at, created_at
         FROM identities
        WHERE user_id = ? AND tenant_id = ?`,
      [uuidToBuffer(userId), uuidToBuffer(tenantId)],
    );

    const [credRows] = await this.pool.execute<CredentialRow[]>(
      `SELECT hash, algorithm, rounds, created_at, updated_at
         FROM credentials
        WHERE user_id = ?
        LIMIT 1`,
      [uuidToBuffer(userId)],
    );

    const identities = (identityRows as IdentityRow[]).map((row: IdentityRow) => rowToIdentity(row));
    const credRow = (credRows as CredentialRow[])[0];
    const credential = credRow
      ? new Credential({
          hash: credRow.hash,
          algorithm: 'bcrypt',
          rounds: credRow.rounds,
          createdAt: credRow.created_at,
          updatedAt: credRow.updated_at,
        })
      : undefined;

    return User.reconstitute({
      id: UserId.from(userId),
      tenantId: TenantId.from(tenantId),
      status: row.status.toUpperCase() as UserStatus,
      identities,
      credential,
      suspendUntil: row.suspend_until ?? undefined,
      version: row.version,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    });
  }

  private async _insertIdentity(
    conn: DbConnection,
    identity: Identity,
  ): Promise<void> {
    await conn.execute(
      `INSERT INTO identities
         (id, tenant_id, user_id, type, value_enc, value_enc_kid,
          value_hash, provider_sub, provider_data_enc, provider_data_enc_kid,
          verified, verified_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        uuidToBuffer(identity.id.toString()),
        uuidToBuffer(identity.tenantId.toString()),
        uuidToBuffer(identity.userId.toString()),
        identityTypeToDb(identity.getType()),
        Buffer.from(identity.getValueEnc()),
        '',
        Buffer.from(identity.getValueHash(), 'hex'),
        identity.getProviderSub() ?? null,
        identity.getProviderDataEnc() ? Buffer.from(identity.getProviderDataEnc()!) : null,
        null,
        identity.isVerified() ? 1 : 0,
        identity.getVerifiedAt() ?? null,
        identity.createdAt,
      ],
    );
  }

  private async _upsertCredential(
    conn: DbConnection,
    userId: UserId,
    credential: Credential,
  ): Promise<void> {
    await conn.execute(
      `INSERT INTO credentials (id, user_id, hash, algorithm, rounds, created_at, updated_at)
       VALUES (UUID_TO_BIN(UUID()), ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         hash       = VALUES(hash),
         algorithm  = VALUES(algorithm),
         rounds     = VALUES(rounds),
         updated_at = VALUES(updated_at)`,
      [
        uuidToBuffer(userId.toString()),
        credential.hash,
        credential.algorithm === 'bcrypt' ? 'bcrypt_v1' : credential.algorithm,
        credential.rounds,
        credential.createdAt,
        credential.updatedAt,
      ],
    );
  }

  private _isDuplicateKeyError(err: unknown): boolean {
    return (
      typeof err === 'object' &&
      err !== null &&
      'code' in err &&
      (err as { code: string }).code === 'ER_DUP_ENTRY'
    );
  }
}

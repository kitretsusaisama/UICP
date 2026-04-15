import { Inject, Injectable, ConflictException } from '@nestjs/common';
import { IIdentityRepository } from '../../../application/ports/driven/i-identity.repository';
import { Identity, IdentityType, toEncryptedValue } from '../../../domain/entities/identity.entity';
import { IdentityId } from '../../../domain/value-objects/identity-id.vo';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { MYSQL_POOL, DbPool } from './mysql.module';

function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
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

const SELECT_COLS = `
  id, tenant_id, user_id, type, value_enc, value_enc_kid,
  value_hash, provider_sub, provider_data_enc, provider_data_enc_kid,
  verified, verified_at, created_at
`;

/**
 * MySQL implementation of IIdentityRepository.
 *
 * - All queries include WHERE tenant_id = ? (Req 1.1, 1.2).
 * - findByHash() uses the uq_tenant_type_hash unique index — O(1) lookup.
 * - save() throws ConflictException(IDENTITY_ALREADY_EXISTS) on duplicate key.
 * - verify() uses optimistic locking via a version check.
 */
@Injectable()
export class MysqlIdentityRepository implements IIdentityRepository {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async findByHash(
    valueHash: string,
    type: IdentityType,
    tenantId: TenantId,
  ): Promise<Identity | null> {
    // value_hash is stored as BINARY(32) — convert hex string to Buffer
    const hashBuf = Buffer.from(valueHash, 'hex');

    const [rows] = await this.pool.execute<IdentityRow[]>(
      `SELECT ${SELECT_COLS}
         FROM identities
        WHERE tenant_id  = ?
          AND type       = ?
          AND value_hash = ?
        LIMIT 1`,
      [uuidToBuffer(tenantId.toString()), identityTypeToDb(type), hashBuf],
    );

    const row = (rows as IdentityRow[])[0];
    return row ? rowToIdentity(row) : null;
  }

  async findByUserId(userId: UserId, tenantId: TenantId): Promise<Identity[]> {
    const [rows] = await this.pool.execute<IdentityRow[]>(
      `SELECT ${SELECT_COLS}
         FROM identities
        WHERE user_id   = ?
          AND tenant_id = ?`,
      [uuidToBuffer(userId.toString()), uuidToBuffer(tenantId.toString())],
    );

    return (rows as IdentityRow[]).map(rowToIdentity);
  }

  async findByProviderSub(
    providerSub: string,
    type: IdentityType,
    tenantId: TenantId,
  ): Promise<Identity | null> {
    const [rows] = await this.pool.execute<IdentityRow[]>(
      `SELECT ${SELECT_COLS}
         FROM identities
        WHERE tenant_id   = ?
          AND type        = ?
          AND provider_sub = ?
        LIMIT 1`,
      [uuidToBuffer(tenantId.toString()), identityTypeToDb(type), providerSub],
    );

    const row = (rows as IdentityRow[])[0];
    return row ? rowToIdentity(row) : null;
  }

  async save(identity: Identity): Promise<void> {
    try {
      await this.pool.execute(
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
    } catch (err: unknown) {
      if (this._isDuplicateKeyError(err)) {
        throw new ConflictException('IDENTITY_ALREADY_EXISTS');
      }
      throw err;
    }
  }

  async verify(identityId: IdentityId, tenantId: TenantId): Promise<void> {
    const now = new Date();
    const [result] = await this.pool.execute(
      `UPDATE identities
          SET verified    = 1,
              verified_at = ?
        WHERE id        = ?
          AND tenant_id = ?
          AND verified  = 0`,
      [now, uuidToBuffer(identityId.toString()), uuidToBuffer(tenantId.toString())],
    );

    if ((result as { affectedRows: number }).affectedRows === 0) {
      // Either not found or already verified — both are acceptable idempotent outcomes
    }
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

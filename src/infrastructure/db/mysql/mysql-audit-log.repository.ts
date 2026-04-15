import { Inject, Injectable, Logger } from '@nestjs/common';
import { createHmac } from 'crypto';
import { ConfigService } from '@nestjs/config';
import {
  IAuditLogRepository,
  AuditLogRecord,
  AuditLogQueryParams,
  PaginatedAuditLogs,
} from '../../../application/ports/driven/i-audit-log.repository';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { MYSQL_POOL, DbPool } from './mysql.module';

function uuidToBuffer(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

function bufferToUuid(buf: Buffer | string): string {
  const hex = Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface AuditLogRow {
  id: Buffer;
  tenant_id: Buffer;
  actor_id: Buffer | null;
  actor_type: string;
  action: string;
  resource_type: string;
  resource_id: Buffer | null;
  metadata_enc: Buffer | null;
  metadata_enc_kid: string | null;
  ip_hash: Buffer | null;
  checksum: Buffer;
  created_at: Date;
}

@Injectable()
export class MysqlAuditLogRepository implements IAuditLogRepository {
  private readonly logger = new Logger(MysqlAuditLogRepository.name);
  private readonly hmacKey: string;

  constructor(
    @Inject(MYSQL_POOL) private readonly pool: DbPool,
    private readonly config: ConfigService,
  ) {
    this.hmacKey = this.config.get<string>('AUDIT_HMAC_KEY') ?? 'default-audit-hmac-key';
  }

  async save(record: AuditLogRecord): Promise<void> {
    const id = record.id.replace(/-/g, '');
    const checksum = this.computeChecksum(record);

    await this.pool.execute(
      `INSERT INTO audit_logs
         (id, tenant_id, actor_id, actor_type, action, resource_type, resource_id,
          metadata_enc, metadata_enc_kid, ip_hash, checksum, created_at)
       VALUES (UNHEX(?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        uuidToBuffer(record.tenantId),
        record.actorId ? uuidToBuffer(record.actorId) : null,
        record.actorType,
        record.action,
        record.resourceType,
        record.resourceId ? uuidToBuffer(record.resourceId) : null,
        record.metadataEnc ?? null,
        record.metadataEncKid ?? null,
        record.ipHash ? Buffer.from(record.ipHash, 'hex') : null,
        checksum,
        record.createdAt,
      ],
    );
  }

  async findByTenantId(tenantId: TenantId, params: AuditLogQueryParams): Promise<PaginatedAuditLogs> {
    const conditions: string[] = ['tenant_id = ?'];
    const bindings: unknown[] = [uuidToBuffer(tenantId.toString())];

    if (params.actorId) {
      conditions.push('actor_id = ?');
      bindings.push(uuidToBuffer(params.actorId));
    }
    if (params.action) {
      conditions.push('action = ?');
      bindings.push(params.action);
    }
    if (params.resourceType) {
      conditions.push('resource_type = ?');
      bindings.push(params.resourceType);
    }
    if (params.since) {
      conditions.push('created_at >= ?');
      bindings.push(params.since);
    }
    if (params.until) {
      conditions.push('created_at <= ?');
      bindings.push(params.until);
    }
    if (params.cursor) {
      conditions.push('created_at < ?');
      bindings.push(new Date(params.cursor));
    }

    const limit = params.limit ?? 50;
    const where = conditions.join(' AND ');

    const [rows] = await this.pool.execute<AuditLogRow[]>(
      `SELECT id, tenant_id, actor_id, actor_type, action, resource_type, resource_id,
              metadata_enc, metadata_enc_kid, ip_hash, checksum, created_at
         FROM audit_logs
        WHERE ${where}
        ORDER BY created_at DESC
        LIMIT ?`,
      [...bindings, limit + 1],
    );

    const allRows = rows as AuditLogRow[];
    const hasMore = allRows.length > limit;
    const pageRows = hasMore ? allRows.slice(0, limit) : allRows;

    const items: AuditLogRecord[] = pageRows.map((row) => {
      const record: AuditLogRecord = {
        id: bufferToUuid(row.id),
        tenantId: bufferToUuid(row.tenant_id),
        actorId: row.actor_id ? bufferToUuid(row.actor_id) : undefined,
        actorType: row.actor_type,
        action: row.action,
        resourceType: row.resource_type,
        resourceId: row.resource_id ? bufferToUuid(row.resource_id) : undefined,
        metadataEnc: row.metadata_enc?.toString('utf8'),
        metadataEncKid: row.metadata_enc_kid ?? undefined,
        ipHash: row.ip_hash?.toString('hex'),
        checksum: row.checksum.toString('hex'),
        createdAt: row.created_at,
      };

      // Verify HMAC checksum on read (Req 12.10)
      const expected = this.computeChecksum(record).toString('hex');
      if (record.checksum !== expected) {
        this.logger.error({ id: record.id }, 'INTEGRITY_VIOLATION: audit log checksum mismatch');
        throw new Error(`INTEGRITY_VIOLATION: audit log ${record.id} has been tampered`);
      }

      return record;
    });

    const [countRows] = await this.pool.execute<[{ total: number }]>(
      `SELECT COUNT(*) AS total FROM audit_logs WHERE ${where}`,
      bindings,
    );
    const total = (countRows as [{ total: number }])[0]?.total ?? 0;

    const lastItem = items[items.length - 1];
    const nextCursor = hasMore && lastItem ? lastItem.createdAt.toISOString() : undefined;

    return { items, nextCursor, total };
  }

  private computeChecksum(record: AuditLogRecord): Buffer {
    const input = [
      record.id,
      record.tenantId,
      record.actorId ?? '',
      record.actorType,
      record.action,
      record.resourceType,
      record.resourceId ?? '',
      record.createdAt.toISOString(),
    ].join('|');

    return createHmac('sha256', this.hmacKey).update(input).digest();
  }
}

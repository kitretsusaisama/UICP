import { Injectable, Inject, Logger } from '@nestjs/common';
import { ListAuditLogsQuery } from './list-audit-logs.query';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { IAuditLogRepository, AuditLogRecord } from '../../ports/driven/i-audit-log.repository';
import { IEncryptionPort } from '../../ports/driven/i-encryption.port';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

export interface AuditLogDto {
  id: string;
  actorId?: string;
  actorType: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
  ipHash?: string;
  createdAt: string;
}

export interface PaginatedAuditLogsDto {
  items: AuditLogDto[];
  nextCursor?: string;
  total: number;
}

/**
 * Query handler — cursor-paginated audit log listing with HMAC integrity verification.
 *
 * Implements: Req 12.1 (HMAC checksum verified on read — throws on tamper),
 *             Req 12.5 (audit log query with filtering and cursor pagination)
 *
 * The repository layer is responsible for HMAC verification on each row.
 * This handler decrypts the metadata field for display.
 */
@Injectable()
export class ListAuditLogsHandler {
  private readonly logger = new Logger(ListAuditLogsHandler.name);

  constructor(
    @Inject(INJECTION_TOKENS.AUDIT_LOG_REPOSITORY)
    private readonly auditLogRepo: IAuditLogRepository,
    @Inject(INJECTION_TOKENS.ENCRYPTION_PORT)
    private readonly encryption: IEncryptionPort,
  ) {}

  async handle(query: ListAuditLogsQuery): Promise<PaginatedAuditLogsDto> {
    const tenantId = TenantId.from(query.tenantId);
    const limit = Math.min(query.limit, 100);

    // Repository handles HMAC verification on every row (Req 12.1)
    const result = await this.auditLogRepo.findByTenantId(tenantId, {
      actorId: query.actorId,
      action: query.action,
      resourceType: query.resourceType,
      since: query.since,
      until: query.until,
      cursor: query.cursor,
      limit,
    });

    const items: AuditLogDto[] = await Promise.all(
      result.items.map((record) => this._toDto(record, tenantId)),
    );

    return {
      items,
      nextCursor: result.nextCursor,
      total: result.total,
    };
  }

  private async _toDto(record: AuditLogRecord, tenantId: TenantId): Promise<AuditLogDto> {
    let metadata: Record<string, unknown> | undefined;

    if (record.metadataEnc) {
      try {
        const decrypted = await this.encryption.decrypt(
          record.metadataEnc as any,
          'AUDIT_METADATA',
          tenantId,
        );
        metadata = JSON.parse(decrypted) as Record<string, unknown>;
      } catch {
        this.logger.warn({ id: record.id }, 'Failed to decrypt audit log metadata');
      }
    }

    return {
      id: record.id,
      actorId: record.actorId,
      actorType: record.actorType,
      action: record.action,
      resourceType: record.resourceType,
      resourceId: record.resourceId,
      metadata,
      ipHash: record.ipHash,
      createdAt: record.createdAt.toISOString(),
    };
  }
}

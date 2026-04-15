import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

export interface AuditLogRecord {
  id: string;
  tenantId: string;
  actorId?: string;
  actorType: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  /** Encrypted metadata blob (AES-256-GCM). */
  metadataEnc?: string;
  metadataEncKid?: string;
  ipHash?: string;
  /** HMAC-SHA256 checksum of immutable fields — verified on read (Req 12.1). */
  checksum: string;
  createdAt: Date;
}

export interface AuditLogQueryParams {
  actorId?: string;
  action?: string;
  resourceType?: string;
  since?: Date;
  until?: Date;
  cursor?: string;
  limit: number;
}

export interface PaginatedAuditLogs {
  items: AuditLogRecord[];
  nextCursor?: string;
  total: number;
}

/**
 * Driven port — audit log persistence.
 *
 * Contract:
 * - `save` is INSERT only — audit logs are immutable (Req 12.1).
 * - `findByTenantId` verifies HMAC checksum on every returned row;
 *   throws `IntegrityViolationException` if any row has been tampered.
 * - Cursor pagination uses (created_at, id) composite key for stable ordering.
 */
export interface IAuditLogRepository {
  /**
   * Persist a new audit log entry (INSERT only).
   */
  save(record: AuditLogRecord): Promise<void>;

  /**
   * Query audit logs for a tenant with optional filtering and cursor pagination.
   * HMAC checksum is verified on every returned row.
   */
  findByTenantId(tenantId: TenantId, params: AuditLogQueryParams): Promise<PaginatedAuditLogs>;
}

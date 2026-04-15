/**
 * Query: cursor-paginated audit log listing with HMAC integrity verification.
 * Implements: Req 12.1 (HMAC checksum verified on read)
 */
export class ListAuditLogsQuery {
  constructor(
    public readonly tenantId: string,
    public readonly limit: number = 50,
    public readonly actorId?: string,
    public readonly action?: string,
    public readonly resourceType?: string,
    public readonly since?: Date,
    public readonly until?: Date,
    /** Opaque cursor from previous page (base64-encoded created_at + id). */
    public readonly cursor?: string,
  ) {}
}

import { Injectable, Inject } from '@nestjs/common';
import { IAuditLogRepository, AUDIT_LOG_REPOSITORY } from '../../../domain/repositories/audit-log.repository.interface';
import { AuditLog } from '../../../domain/entities/audit-log.entity';

@Injectable()
export class AuditService {
  constructor(
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async listLogs(tenantId: string, limit = 50, cursor?: string) {
    return this.auditRepo.list(tenantId, limit, cursor);
  }

  async *exportLogs(tenantId: string, options: { from?: string; to?: string }) {
    // Basic streaming export simulation
    // A production stream would utilize MySQL streams for low memory
    let cursor: string | undefined;
    let hasMore = true;

    while (hasMore) {
      const result = await this.auditRepo.list(tenantId, 100, cursor);
      for (const log of result.data) {
        yield log;
      }
      cursor = result.nextCursor;
      if (!cursor || result.data.length === 0) {
        hasMore = false;
      }
    }
  }
}

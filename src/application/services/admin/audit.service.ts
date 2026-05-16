import { Inject, Injectable } from '@nestjs/common';
import {
  AuditLogQueryParams,
  IAuditLogRepository,
} from '../../ports/driven/i-audit-log.repository';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

@Injectable()
export class AuditService {
  constructor(
    @Inject(INJECTION_TOKENS.AUDIT_LOG_REPOSITORY)
    private readonly auditRepo: IAuditLogRepository,
  ) {}

  async listLogs(tenantId: string, limit = 50, cursor?: string) {
    const params: AuditLogQueryParams = { limit, cursor };
    return this.auditRepo.findByTenantId(TenantId.from(tenantId), params);
  }
}

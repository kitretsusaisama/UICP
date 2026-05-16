import { Injectable } from '@nestjs/common';

@Injectable()
export class AdminUserService {
  async summarizeTenantUsers(tenantId: string) {
    return {
      tenantId,
      total: 0,
      active: 0,
      locked: 0,
    };
  }
}

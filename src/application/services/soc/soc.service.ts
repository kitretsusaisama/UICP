import { Injectable } from '@nestjs/common';

@Injectable()
export class SocService {
  async summarizeTenantRisk(tenantId: string) {
    return {
      tenantId,
      openAlerts: 0,
      replayEvents: 0,
      providerIncidents: 0,
    };
  }
}

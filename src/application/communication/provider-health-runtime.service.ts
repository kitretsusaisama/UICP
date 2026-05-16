import { Injectable } from '@nestjs/common';
import { ProviderHealthResult } from './communication.types';

@Injectable()
export class ProviderHealthRuntime {
  private readonly latest = new Map<string, ProviderHealthResult>();

  record(tenantId: string, health: ProviderHealthResult): ProviderHealthResult {
    this.latest.set(`${tenantId}:${health.providerName}`, health);
    return health;
  }

  list(tenantId: string): ProviderHealthResult[] {
    return [...this.latest.entries()]
      .filter(([key]) => key.startsWith(`${tenantId}:`))
      .map(([, value]) => value);
  }
}

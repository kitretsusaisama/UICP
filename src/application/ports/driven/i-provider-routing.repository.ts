export interface ProviderRoutingRuleRecord {
  tenantId?: string;
  channel: 'SMS' | 'EMAIL';
  purpose: string;
  countryCode?: string;
  priority: number;
  providerKey: string;
  fallbackOnError: boolean;
  enabled: boolean;
  version: number;
}

export interface IProviderRoutingRepository {
  listRules(tenantId?: string): Promise<ProviderRoutingRuleRecord[]>;
}

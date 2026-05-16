import { createTenantFixture, getTenantCredentials, TenantConfig } from '../helpers/tenant-factory';

export const tenantAConfig: TenantConfig = createTenantFixture('A');
export const tenantBConfig: TenantConfig = createTenantFixture('B');
export const tenantCConfig: TenantConfig = createTenantFixture('C');

export const tenantACredentials = getTenantCredentials('A');
export const tenantBCredentials = getTenantCredentials('B');
export const tenantCCredentials = getTenantCredentials('C');

// Cross-tenant test scenarios
export const crossTenantScenarios = {
  sameApiKey: {
    description: 'Both tenants using same API key',
    setup: () => ({
      tenantA: { ...tenantAConfig, apiKey: 'shared_key' },
      tenantB: { ...tenantBConfig, apiKey: 'shared_key' },
    }),
    shouldFail: true,
  },
  sameSenderId: {
    description: 'Both tenants using same sender ID',
    setup: () => ({
      tenantA: { ...tenantAConfig, senderId: 'SHARED' },
      tenantB: { ...tenantBConfig, senderId: 'SHARED' },
    }),
    shouldFail: true,
  },
  isolated: {
    description: 'Tenants with complete isolation',
    setup: () => ({
      tenantA: tenantAConfig,
      tenantB: tenantBConfig,
    }),
    shouldFail: false,
  },
};
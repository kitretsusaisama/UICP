import { createTenantFixture, getTenantCredentials, TenantConfig } from '../helpers/tenant-factory';

// Tenant B specific configuration for isolation tests
export const tenantBFullConfig: TenantConfig = {
  ...createTenantFixture('B'),
  // Additional tenant B specific settings
  customSettings: {
    otpLength: 6,
    otpExpirySeconds: 300,
    maxRetries: 3,
    retryDelaySeconds: 30,
  },
  webhookConfig: {
    enabled: true,
    url: 'https://tenant-b.example.com/webhooks/otp',
    events: ['otp.sent', 'otp.delivered', 'otp.failed'],
  },
  rateLimitConfig: {
    perMinute: 50,
    perHour: 1000,
    perDay: 5000,
  },
  branding: {
    primaryColor: '#0066FF',
    logoUrl: 'https://tenant-b.example.com/logo.png',
    companyName: 'Tenant B Corp',
  },
};

export const tenantBCredentialsFull = getTenantCredentials('B');

// Import tenant A for cross-tenant isolation validation
import { tenantAConfig } from './tenant-a-config';

export function validateIsolation(): {
  isolated: boolean;
  violations: Array<{ field: string; tenantAValue: unknown; tenantBValue: unknown }>;
} {
  const violations: Array<{ field: string; tenantAValue: unknown; tenantBValue: unknown }> = [];

  // Validate that tenant A and B configs are properly isolated
  if (tenantAConfig.apiKey === tenantBFullConfig.apiKey) {
    violations.push({
      field: 'apiKey',
      tenantAValue: tenantAConfig.apiKey,
      tenantBValue: tenantBFullConfig.apiKey,
    });
  }

  if (tenantAConfig.senderId === tenantBFullConfig.senderId) {
    violations.push({
      field: 'senderId',
      tenantAValue: tenantAConfig.senderId,
      tenantBValue: tenantBFullConfig.senderId,
    });
  }

  if (tenantAConfig.fromEmail === tenantBFullConfig.fromEmail) {
    violations.push({
      field: 'fromEmail',
      tenantAValue: tenantAConfig.fromEmail,
      tenantBValue: tenantBFullConfig.fromEmail,
    });
  }

  if (tenantAConfig.id === tenantBFullConfig.id) {
    violations.push({
      field: 'id',
      tenantAValue: tenantAConfig.id,
      tenantBValue: tenantBFullConfig.id,
    });
  }

  return {
    isolated: violations.length === 0,
    violations,
  };
}
import { v4 as uuidv4 } from 'crypto';

export interface TenantConfig {
  id: string;
  name: string;
  smsProvider: string;
  emailProvider: string;
  senderId: string;
  fromEmail: string;
  apiKey: string;
  apiSecret?: string;
  region?: string;
  priority: number;
  isPrimary: boolean;
  rateLimitPerMin: number;
  dailyLimit: number;
}

export interface TenantCredentials {
  sms: {
    providerKey: string;
    apiKey: string;
    apiSecret?: string;
    senderId: string;
  };
  email: {
    providerKey: string;
    apiKey: string;
    fromEmail: string;
    fromName?: string;
    domain?: string;
  };
}

// Generate deterministic tenant IDs for testing
const TENANT_A_ID = '11111111-1111-1111-1111-111111111111';
const TENANT_B_ID = '22222222-2222-2222-2222-222222222222';
const TENANT_C_ID = '33333333-3333-3333-3333-333333333333';

export function createTenantId(tenant: 'A' | 'B' | 'C' | number): string {
  switch (tenant) {
    case 'A': return TENANT_A_ID;
    case 'B': return TENANT_B_ID;
    case 'C': return TENANT_C_ID;
    default: return uuidv4();
  }
}

export function createTenantFixture(tenant: 'A' | 'B' | 'C'): TenantConfig {
  switch (tenant) {
    case 'A':
      return {
        id: TENANT_A_ID,
        name: 'TenantA',
        smsProvider: 'MSG91',
        emailProvider: 'RESEND',
        senderId: 'APPA',
        fromEmail: 'noreply@tenant-a.com',
        apiKey: 're_test_tenant_a_key_12345',
        region: 'us-east-1',
        priority: 1,
        isPrimary: true,
        rateLimitPerMin: 100,
        dailyLimit: 10000,
      };
    case 'B':
      return {
        id: TENANT_B_ID,
        name: 'TenantB',
        smsProvider: 'TWILIO',
        emailProvider: 'MAILEROO',
        senderId: 'APPB',
        fromEmail: 'auth@tenant-b.com',
        apiKey: 'ma_test_tenant_b_key_67890',
        apiSecret: 'twilio_secret_tenant_b',
        region: 'us-west-2',
        priority: 2,
        isPrimary: false,
        rateLimitPerMin: 50,
        dailyLimit: 5000,
      };
    case 'C':
      return {
        id: TENANT_C_ID,
        name: 'TenantC',
        smsProvider: 'AWS_SNS',
        emailProvider: 'AWS_SES',
        senderId: 'APPC',
        fromEmail: 'support@tenant-c.com',
        apiKey: 'aws_tenant_c_key',
        apiSecret: 'aws_secret_tenant_c',
        region: 'eu-west-1',
        priority: 3,
        isPrimary: false,
        rateLimitPerMin: 200,
        dailyLimit: 20000,
      };
  }
}

export function getTenantCredentials(tenant: 'A' | 'B' | 'C'): TenantCredentials {
  switch (tenant) {
    case 'A':
      return {
        sms: {
          providerKey: 'MSG91',
          apiKey: 'msg91_test_key_A',
          apiSecret: 'msg91_secret_A',
          senderId: 'APPA',
        },
        email: {
          providerKey: 'RESEND',
          apiKey: 're_test_tenant_a_key_12345',
          fromEmail: 'noreply@tenant-a.com',
          fromName: 'Tenant A',
          domain: 'tenant-a.com',
        },
      };
    case 'B':
      return {
        sms: {
          providerKey: 'TWILIO',
          apiKey: 'twilio_test_key_B',
          apiSecret: 'twilio_secret_B',
          senderId: 'APPB',
        },
        email: {
          providerKey: 'MAILEROO',
          apiKey: 'ma_test_tenant_b_key_67890',
          fromEmail: 'auth@tenant-b.com',
          fromName: 'Tenant B',
          domain: 'tenant-b.com',
        },
      };
    case 'C':
      return {
        sms: {
          providerKey: 'AWS_SNS',
          apiKey: 'aws_key_C',
          apiSecret: 'aws_secret_C',
          senderId: 'APPC',
        },
        email: {
          providerKey: 'AWS_SES',
          apiKey: 'aws_key_C',
          fromEmail: 'support@tenant-c.com',
          fromName: 'Tenant C',
          domain: 'tenant-c.com',
        },
      };
  }
}

// Tenant cache keys (used for Redis)
export function tenantCacheKey(tenantId: string, key: string): string {
  return `tenant:${tenantId}:${key}`;
}

export function providerCacheKey(tenantId: string, channel: string): string {
  return `tenant:${tenantId}:provider:${channel}`;
}

// Validation helpers
export function validateTenantIsolation(tenantA: TenantConfig, tenantB: TenantConfig): { valid: boolean; leaks: string[] } {
  const leaks: string[] = [];

  // Check API key isolation
  if (tenantA.apiKey === tenantB.apiKey) {
    leaks.push('API key leak');
  }

  // Check sender ID isolation
  if (tenantA.senderId === tenantB.senderId) {
    leaks.push('senderId leak');
  }

  // Check from email isolation
  if (tenantA.fromEmail === tenantB.fromEmail) {
    leaks.push('fromEmail leak');
  }

  return {
    valid: leaks.length === 0,
    leaks,
  };
}

export const tenantA = createTenantFixture('A');
export const tenantB = createTenantFixture('B');
export const tenantC = createTenantFixture('C');

export const tenantACreds = getTenantCredentials('A');
export const tenantBCreds = getTenantCredentials('B');
export const tenantCCreds = getTenantCredentials('C');
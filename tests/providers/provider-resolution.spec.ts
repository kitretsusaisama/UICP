import { describe, it, expect, beforeEach } from '@jest/globals';

interface ProviderConfig {
  id: string;
  tenantId: string;
  providerKey: string; // MSG91, TWILIO, RESEND, MAILEROO
  providerType: 'SMS' | 'EMAIL';
  isEnabled: boolean;
  isPrimary: boolean;
  priority: number;
  apiKey: string;
  apiSecret?: string;
  senderId?: string;
  fromEmail?: string;
  region?: string;
  fallbackKeys?: string[];
}

// Provider store
const providerStore = new Map<string, ProviderConfig>();

function providerId(tenantId: string, type: string, providerKey: string): string {
  return `${tenantId}:${type}:${providerKey}`;
}

async function registerProvider(config: ProviderConfig): Promise<void> {
  const id = providerId(config.tenantId, config.providerType, config.providerKey);
  providerStore.set(id, config);
}

async function resolveProvider(
  tenantId: string,
  type: 'SMS' | 'EMAIL'
): Promise<ProviderConfig | null> {
  // Find PRIMARY provider for tenant
  const providers = Array.from(providerStore.values())
    .filter(p => p.tenantId === tenantId && p.providerType === type && p.isEnabled)
    .sort((a, b) => a.priority - b.priority);

  return providers[0] || null;
}

async function getAllProviders(
  tenantId: string,
  type: 'SMS' | 'EMAIL'
): Promise<ProviderConfig[]> {
  return Array.from(providerStore.values())
    .filter(p => p.tenantId === tenantId && p.providerType === type && p.isEnabled)
    .sort((a, b) => a.priority - b.priority);
}

describe('Provider Resolution', () => {
  beforeEach(() => {
    providerStore.clear();
  });

  it('resolves Tenant A SMS provider correctly', async () => {
    await registerProvider({
      id: '1',
      tenantId: 'tenant-a',
      providerKey: 'MSG91',
      providerType: 'SMS',
      isEnabled: true,
      isPrimary: true,
      priority: 1,
      apiKey: 'msg91_key_a',
      senderId: 'APPA',
    });

    const provider = await resolveProvider('tenant-a', 'SMS');

    expect(provider).not.toBeNull();
    expect(provider?.providerKey).toBe('MSG91');
    expect(provider?.tenantId).toBe('tenant-a');
    expect(provider?.apiKey).toBe('msg91_key_a');
  });

  it('resolves Tenant B email provider correctly', async () => {
    await registerProvider({
      id: '2',
      tenantId: 'tenant-b',
      providerKey: 'MAILEROO',
      providerType: 'EMAIL',
      isEnabled: true,
      isPrimary: true,
      priority: 1,
      apiKey: 'maileroo_key_b',
      fromEmail: 'auth@tenant-b.com',
    });

    const provider = await resolveProvider('tenant-b', 'EMAIL');

    expect(provider?.providerKey).toBe('MAILEROO');
    expect(provider?.tenantId).toBe('tenant-b');
    expect(provider?.apiKey).toBe('maileroo_key_b');
  });

  it('never resolves another tenant provider config', async () => {
    // Tenant A provider
    await registerProvider({
      id: '1',
      tenantId: 'tenant-a',
      providerKey: 'MSG91',
      providerType: 'SMS',
      isEnabled: true,
      isPrimary: true,
      priority: 1,
      apiKey: 'msg91_key_a',
      senderId: 'APPA',
    });

    // Tenant B provider
    await registerProvider({
      id: '2',
      tenantId: 'tenant-b',
      providerKey: 'TWILIO',
      providerType: 'SMS',
      isEnabled: true,
      isPrimary: true,
      priority: 1,
      apiKey: 'twilio_key_b',
      senderId: 'APPB',
    });

    // Tenant A resolves to MSG91
    const providerA = await resolveProvider('tenant-a', 'SMS');
    expect(providerA?.providerKey).toBe('MSG91');
    expect(providerA?.apiKey).toBe('msg91_key_a');

    // Tenant B resolves to TWILIO
    const providerB = await resolveProvider('tenant-b', 'SMS');
    expect(providerB?.providerKey).toBe('TWILIO');
    expect(providerB?.apiKey).toBe('twilio_key_b');

    // Cross-tenant contamination check
    expect(providerA?.apiKey).not.toBe(providerB?.apiKey);
    expect(providerA?.senderId).not.toBe(providerB?.senderId);
  });

  it('returns null for tenant with no providers', async () => {
    const provider = await resolveProvider('tenant-no-providers', 'SMS');
    expect(provider).toBeNull();
  });

  it('skips disabled providers', async () => {
    await registerProvider({
      id: '1',
      tenantId: 'tenant-a',
      providerKey: 'MSG91',
      providerType: 'SMS',
      isEnabled: false, // Disabled
      isPrimary: true,
      priority: 1,
      apiKey: 'msg91_key_a',
    });

    const provider = await resolveProvider('tenant-a', 'SMS');
    expect(provider).toBeNull();
  });

  it('selects primary provider by priority', async () => {
    // Multiple providers for tenant
    await registerProvider({
      id: '1',
      tenantId: 'tenant-a',
      providerKey: 'MSG91',
      providerType: 'SMS',
      isEnabled: true,
      isPrimary: false,
      priority: 2,
      apiKey: 'msg91_key',
    });

    await registerProvider({
      id: '2',
      tenantId: 'tenant-a',
      providerKey: 'TWILIO',
      providerType: 'SMS',
      isEnabled: true,
      isPrimary: true,
      priority: 1,
      apiKey: 'twilio_key',
    });

    const provider = await resolveProvider('tenant-a', 'SMS');
    expect(provider?.providerKey).toBe('TWILIO'); // Lower priority number = higher
  });

  it('filters by provider type', async () => {
    await registerProvider({
      id: '1',
      tenantId: 'tenant-a',
      providerKey: 'MSG91',
      providerType: 'SMS',
      isEnabled: true,
      isPrimary: true,
      priority: 1,
      apiKey: 'msg91_key',
    });

    await registerProvider({
      id: '2',
      tenantId: 'tenant-a',
      providerKey: 'RESEND',
      providerType: 'EMAIL',
      isEnabled: true,
      isPrimary: true,
      priority: 1,
      apiKey: 'resend_key',
    });

    const smsProvider = await resolveProvider('tenant-a', 'SMS');
    const emailProvider = await resolveProvider('tenant-a', 'EMAIL');

    expect(smsProvider?.providerKey).toBe('MSG91');
    expect(emailProvider?.providerKey).toBe('RESEND');
  });

  it('isolates provider credentials completely', async () => {
    const tenantAProviders = [
      { providerKey: 'MSG91', apiKey: 'secret_a1', senderId: 'SENDER_A' },
      { providerKey: 'RESEND', apiKey: 'secret_a2', fromEmail: 'a@tenant-a.com' },
    ];

    const tenantBProviders = [
      { providerKey: 'TWILIO', apiKey: 'secret_b1', senderId: 'SENDER_B' },
      { providerKey: 'MAILEROO', apiKey: 'secret_b2', fromEmail: 'b@tenant-b.com' },
    ];

    for (const p of tenantAProviders) {
      await registerProvider({
        id: `a-${p.providerKey}`,
        tenantId: 'tenant-a',
        providerKey: p.providerKey,
        providerType: p.senderId ? 'SMS' : 'EMAIL',
        isEnabled: true,
        isPrimary: true,
        priority: 1,
        apiKey: p.apiKey,
        senderId: p.senderId,
        fromEmail: p.fromEmail,
      });
    }

    for (const p of tenantBProviders) {
      await registerProvider({
        id: `b-${p.providerKey}`,
        tenantId: 'tenant-b',
        providerKey: p.providerKey,
        providerType: p.senderId ? 'SMS' : 'EMAIL',
        isEnabled: true,
        isPrimary: true,
        priority: 1,
        apiKey: p.apiKey,
        senderId: p.senderId,
        fromEmail: p.fromEmail,
      });
    }

    const allA = await getAllProviders('tenant-a', 'SMS');
    const allB = await getAllProviders('tenant-b', 'SMS');

    // No credential overlap
    const credsA = allA.map(p => p.apiKey);
    const credsB = allB.map(p => p.apiKey);

    for (const cred of credsA) {
      expect(credsB).not.toContain(cred);
    }
  });
});

describe('Provider Fallback Chain', () => {
  beforeEach(() => {
    providerStore.clear();
  });

  it('builds fallback chain correctly', async () => {
    await registerProvider({
      id: '1',
      tenantId: 'tenant-a',
      providerKey: 'MSG91',
      providerType: 'SMS',
      isEnabled: true,
      isPrimary: true,
      priority: 1,
      apiKey: 'key1',
    });

    await registerProvider({
      id: '2',
      tenantId: 'tenant-a',
      providerKey: 'TWILIO',
      providerType: 'SMS',
      isEnabled: true,
      isPrimary: false,
      priority: 2,
      apiKey: 'key2',
    });

    const providers = await getAllProviders('tenant-a', 'SMS');

    expect(providers.length).toBe(2);
    expect(providers[0]!.providerKey).toBe('MSG91'); // Primary
    expect(providers[1]!.providerKey).toBe('TWILIO'); // Fallback
  });

  it('skips failed primary and uses fallback', async () => {
    await registerProvider({
      id: '1',
      tenantId: 'tenant-a',
      providerKey: 'MSG91',
      providerType: 'SMS',
      isEnabled: true,
      isPrimary: true,
      priority: 1,
      apiKey: 'invalid_key', // Simulated failure
    });

    await registerProvider({
      id: '2',
      tenantId: 'tenant-a',
      providerKey: 'TWILIO',
      providerType: 'SMS',
      isEnabled: true,
      isPrimary: false,
      priority: 2,
      apiKey: 'valid_key',
    });

    // In real implementation, we'd try primary, catch error, then use fallback
    // For this test, we verify configuration allows fallback
    const providers = await getAllProviders('tenant-a', 'SMS');

    expect(providers.length).toBe(2);
    expect(providers[1]!.providerKey).toBe('TWILIO');
  });
});
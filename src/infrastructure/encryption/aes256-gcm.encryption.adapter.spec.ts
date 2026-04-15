import * as fc from 'fast-check';
import { ConfigService } from '@nestjs/config';
import { Aes256GcmEncryptionAdapter } from './aes256-gcm.encryption.adapter';
import { EncryptionContext } from '../../application/ports/driven/i-encryption.port';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';

// ── Test helpers ──────────────────────────────────────────────────────────────

const MASTER_KEY_HEX = 'a'.repeat(64); // 32-byte test key
const MASTER_KID = 'test-kid-1';

function makeAdapter(overrides: Record<string, string | undefined> = {}): Aes256GcmEncryptionAdapter {
  const cfg: Record<string, string | undefined> = {
    ENCRYPTION_MASTER_KEY: MASTER_KEY_HEX,
    ENCRYPTION_MASTER_KEY_ID: MASTER_KID,
    ...overrides,
  };

  const configService = {
    getOrThrow: (key: string) => {
      const val = cfg[key];
      if (val === undefined) throw new Error(`Missing config: ${key}`);
      return val;
    },
    get: (key: string) => cfg[key],
  } as unknown as ConfigService;

  return new Aes256GcmEncryptionAdapter(configService);
}

async function buildAdapter(overrides: Record<string, string | undefined> = {}): Promise<Aes256GcmEncryptionAdapter> {
  const adapter = makeAdapter(overrides);
  // Call loadKeys + validateEncryptionKeys via onModuleInit
  await adapter.onModuleInit();
  return adapter;
}

const ALL_CONTEXTS: EncryptionContext[] = [
  'IDENTITY_VALUE',
  'USER_PII',
  'AUDIT_METADATA',
  'TENANT_SETTINGS',
  'OAUTH_PROVIDER_DATA',
  'JWT_PRIVATE_KEY',
];

const tenantA = TenantId.from('11111111-1111-4111-8111-111111111111');
const tenantB = TenantId.from('22222222-2222-4222-8222-222222222222');

// ── Property 7: Encryption roundtrip ─────────────────────────────────────────

describe('Property 7 — encrypt/decrypt roundtrip', () => {
  let adapter: Aes256GcmEncryptionAdapter;

  beforeAll(async () => {
    adapter = await buildAdapter();
  });

  it('decrypt(encrypt(p, ctx, tid), ctx, tid) === p for all plaintexts and contexts', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 1000 }),
        fc.constantFrom(...ALL_CONTEXTS),
        async (plaintext, context) => {
          const encrypted = await adapter.encrypt(plaintext, context, tenantA);
          const decrypted = await adapter.decrypt(encrypted, context, tenantA);
          return decrypted === plaintext;
        },
      ),
      { numRuns: 50 },
    );
  });

  it('roundtrip works for all contexts with explicit tenant', async () => {
    for (const context of ALL_CONTEXTS) {
      const plaintext = `test-value-for-${context}`;
      const encrypted = await adapter.encrypt(plaintext, context, tenantA);
      const decrypted = await adapter.decrypt(encrypted, context, tenantA);
      expect(decrypted).toBe(plaintext);
    }
  });

  it('each encryption of the same plaintext produces a different ciphertext (random IV)', async () => {
    const plaintext = 'same-plaintext';
    const enc1 = await adapter.encrypt(plaintext, 'IDENTITY_VALUE', tenantA);
    const enc2 = await adapter.encrypt(plaintext, 'IDENTITY_VALUE', tenantA);
    expect(enc1).not.toBe(enc2);
  });
});

// ── Property 8: HMAC determinism ─────────────────────────────────────────────

describe('Property 8 — HMAC determinism', () => {
  let adapter: Aes256GcmEncryptionAdapter;

  beforeAll(async () => {
    adapter = await buildAdapter();
  });

  it('hmac(v, ctx) === hmac(v, ctx) — same input always produces same output', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string(),
        fc.constantFrom(...ALL_CONTEXTS),
        async (value, context) => {
          const h1 = await adapter.hmac(value, context);
          const h2 = await adapter.hmac(value, context);
          return h1 === h2;
        },
      ),
      { numRuns: 50 },
    );
  });

  it('hmac produces different outputs for different contexts', async () => {
    const value = 'test@example.com';
    const h1 = await adapter.hmac(value, 'IDENTITY_VALUE');
    const h2 = await adapter.hmac(value, 'USER_PII');
    expect(h1).not.toBe(h2);
  });

  it('hmac produces different outputs for different values', async () => {
    const h1 = await adapter.hmac('alice@example.com', 'IDENTITY_VALUE');
    const h2 = await adapter.hmac('bob@example.com', 'IDENTITY_VALUE');
    expect(h1).not.toBe(h2);
  });
});

// ── Property 9.3: Cross-context encryption isolation ─────────────────────────

describe('Cross-context encryption isolation', () => {
  let adapter: Aes256GcmEncryptionAdapter;

  beforeAll(async () => {
    adapter = await buildAdapter();
  });

  it('decrypting with a different context always fails (GCM auth tag mismatch)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 200 }),
        fc.integer({ min: 0, max: ALL_CONTEXTS.length - 1 }),
        fc.integer({ min: 0, max: ALL_CONTEXTS.length - 1 }),
        async (plaintext, idxA, idxB) => {
          fc.pre(idxA !== idxB);
          const ctxA = ALL_CONTEXTS[idxA]!;
          const ctxB = ALL_CONTEXTS[idxB]!;

          const encrypted = await adapter.encrypt(plaintext, ctxA, tenantA);
          await expect(adapter.decrypt(encrypted, ctxB, tenantA)).rejects.toThrow(
            'DECRYPTION_FAILED',
          );
          return true;
        },
      ),
      { numRuns: 30 },
    );
  });

  it('decrypting with a different tenant always fails', async () => {
    const plaintext = 'sensitive-data';
    const encrypted = await adapter.encrypt(plaintext, 'IDENTITY_VALUE', tenantA);
    await expect(adapter.decrypt(encrypted, 'IDENTITY_VALUE', tenantB)).rejects.toThrow(
      'DECRYPTION_FAILED',
    );
  });

  it('all context pairs are isolated from each other', async () => {
    const plaintext = 'isolation-test';
    for (const ctxA of ALL_CONTEXTS) {
      const encrypted = await adapter.encrypt(plaintext, ctxA, tenantA);
      for (const ctxB of ALL_CONTEXTS) {
        if (ctxA === ctxB) continue;
        await expect(adapter.decrypt(encrypted, ctxB, tenantA)).rejects.toThrow(
          'DECRYPTION_FAILED',
        );
      }
    }
  });
});

// ── Envelope encryption (large fields) ───────────────────────────────────────

describe('encryptLarge / decryptLarge', () => {
  let adapter: Aes256GcmEncryptionAdapter;

  beforeAll(async () => {
    adapter = await buildAdapter();
  });

  it('roundtrip works for large plaintext', async () => {
    const plaintext = 'x'.repeat(5000);
    const encrypted = await adapter.encryptLarge(plaintext, 'USER_PII', tenantA);
    const decrypted = await adapter.decryptLarge(encrypted, 'USER_PII', tenantA);
    expect(decrypted).toBe(plaintext);
  });

  it('cross-context isolation holds for large fields', async () => {
    const plaintext = 'large-sensitive-data';
    const encrypted = await adapter.encryptLarge(plaintext, 'AUDIT_METADATA', tenantA);
    await expect(
      adapter.decryptLarge(encrypted, 'USER_PII', tenantA),
    ).rejects.toThrow('DECRYPTION_FAILED');
  });

  it('cross-tenant isolation holds for large fields', async () => {
    const plaintext = 'large-sensitive-data';
    const encrypted = await adapter.encryptLarge(plaintext, 'AUDIT_METADATA', tenantA);
    await expect(
      adapter.decryptLarge(encrypted, 'AUDIT_METADATA', tenantB),
    ).rejects.toThrow('DECRYPTION_FAILED');
  });
});

// ── Key rotation support ──────────────────────────────────────────────────────

describe('Key rotation — deprecated key decryption', () => {
  it('can decrypt values encrypted with a deprecated key', async () => {
    // Simulate: value was encrypted with the "old" key
    const oldKeyHex = 'b'.repeat(64);
    const oldKid = 'old-kid';

    const oldAdapter = await buildAdapter({
      ENCRYPTION_MASTER_KEY: oldKeyHex,
      ENCRYPTION_MASTER_KEY_ID: oldKid,
    });

    const plaintext = 'encrypted-with-old-key';
    const encrypted = await oldAdapter.encrypt(plaintext, 'IDENTITY_VALUE', tenantA);

    // New adapter has new active key but old key as deprecated
    const newAdapter = await buildAdapter({
      ENCRYPTION_MASTER_KEY: MASTER_KEY_HEX,
      ENCRYPTION_MASTER_KEY_ID: MASTER_KID,
      ENCRYPTION_DEPRECATED_KEY: oldKeyHex,
      ENCRYPTION_DEPRECATED_KEY_ID: oldKid,
    });

    const decrypted = await newAdapter.decrypt(encrypted, 'IDENTITY_VALUE', tenantA);
    expect(decrypted).toBe(plaintext);
  });

  it('throws on unknown kid', async () => {
    const adapter = await buildAdapter();
    // Craft a value with an unknown kid
    const fakeEncrypted = 'aXY=.dGFn.Y2lwaGVydGV4dA==.unknown-kid-xyz' as any;
    await expect(adapter.decrypt(fakeEncrypted, 'IDENTITY_VALUE', tenantA)).rejects.toThrow(
      "unknown key id 'unknown-kid-xyz'",
    );
  });
});

// ── Startup validation ────────────────────────────────────────────────────────

describe('validateEncryptionKeys', () => {
  it('passes with valid keys', async () => {
    const adapter = makeAdapter();
    await expect(adapter.onModuleInit()).resolves.not.toThrow();
  });

  it('throws if master key is wrong length', () => {
    const adapter = makeAdapter({ ENCRYPTION_MASTER_KEY: 'tooshort' });
    // loadKeys is called inside onModuleInit; it will throw synchronously
    expect(() => {
      // Access private method via cast to test key loading
      (adapter as any).loadKeys();
    }).toThrow();
  });
});

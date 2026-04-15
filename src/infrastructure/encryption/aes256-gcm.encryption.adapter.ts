import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  randomBytes,
} from 'node:crypto';

import {
  EncryptionContext,
  IEncryptionPort,
} from '../../application/ports/driven/i-encryption.port';
import { EncryptedValue, toEncryptedValue } from '../../domain/entities/identity.entity';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';

/** AES-256-GCM constants */
const IV_BYTES = 12;   // 96-bit nonce — recommended for GCM
const TAG_BYTES = 16;  // 128-bit authentication tag
const KEY_BYTES = 32;  // 256-bit derived key

/**
 * Serialized format: `base64(iv).base64(tag).base64(ciphertext).kid`
 * The `kid` identifies which master key was used, enabling key rotation.
 */
const SEPARATOR = '.';

/**
 * Envelope encryption format for large fields (> 4KB).
 * Stored as: `base64(encryptedDek).base64(dekIv).base64(dekTag).base64(encryptedData).base64(dataIv).base64(dataTag).kid`
 */
const LARGE_FIELD_MARKER = 'env:';

interface MasterKey {
  kid: string;
  key: Buffer;
}

/**
 * AES-256-GCM field-level encryption adapter.
 *
 * Key derivation: HKDF(masterKey, salt=tenantId, info=context || tenantId) → 256-bit context key.
 * Serialization: base64(iv).base64(tag).base64(ciphertext).kid
 *
 * Implements Req 13.1–13.9.
 */
@Injectable()
export class Aes256GcmEncryptionAdapter implements IEncryptionPort, OnModuleInit {
  private readonly logger = new Logger(Aes256GcmEncryptionAdapter.name);

  /** Active key used for all new encryptions. */
  private activeKey!: MasterKey;

  /** All keys (active + deprecated) indexed by kid for decryption. */
  private readonly keyring = new Map<string, Buffer>();

  constructor(private readonly config: ConfigService) {}

  async onModuleInit(): Promise<void> {
    this.loadKeys();
    await this.validateEncryptionKeys();
  }

  // ── IEncryptionPort ────────────────────────────────────────────────────────

  async encrypt(
    plaintext: string,
    context: EncryptionContext,
    tenantId: TenantId,
  ): Promise<EncryptedValue> {
    const contextKey = this.deriveContextKey(this.activeKey.key, context, tenantId);
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', contextKey, iv);

    const ciphertext = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    const serialized = [
      iv.toString('base64'),
      tag.toString('base64'),
      ciphertext.toString('base64'),
      this.activeKey.kid,
    ].join(SEPARATOR);

    return toEncryptedValue(serialized);
  }

  async decrypt(
    encryptedValue: EncryptedValue,
    context: EncryptionContext,
    tenantId: TenantId,
  ): Promise<string> {
    const raw = encryptedValue as string;

    if (raw.startsWith(LARGE_FIELD_MARKER)) {
      return this.decryptLarge(encryptedValue, context, tenantId);
    }

    const parts = raw.split(SEPARATOR);
    if (parts.length !== 4) {
      throw new Error('DECRYPTION_FAILED: invalid encrypted value format');
    }

    const [ivB64, tagB64, ciphertextB64, kid] = parts as [string, string, string, string];
    const masterKey = this.keyring.get(kid);
    if (!masterKey) {
      throw new Error(`DECRYPTION_FAILED: unknown key id '${kid}'`);
    }

    const contextKey = this.deriveContextKey(masterKey, context, tenantId);
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const ciphertext = Buffer.from(ciphertextB64, 'base64');

    try {
      const decipher = createDecipheriv('aes-256-gcm', contextKey, iv);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return plaintext.toString('utf8');
    } catch {
      throw new Error('DECRYPTION_FAILED: GCM authentication tag mismatch');
    }
  }

  async hmac(value: string, context: EncryptionContext): Promise<string> {
    // HMAC uses the active master key with a context-specific info string.
    // No tenantId — HMAC is used for cross-tenant identity lookups (email/phone dedup).
    const hmacKey = this.deriveHmacKey(this.activeKey.key, context);
    return createHmac('sha256', hmacKey).update(value, 'utf8').digest('hex');
  }

  async encryptLarge(
    plaintext: string,
    context: EncryptionContext,
    tenantId: TenantId,
  ): Promise<EncryptedValue> {
    // 1. Generate a random 256-bit DEK
    const dek = randomBytes(KEY_BYTES);

    // 2. Encrypt the plaintext with the DEK
    const dataIv = randomBytes(IV_BYTES);
    const dataCipher = createCipheriv('aes-256-gcm', dek, dataIv);
    const encryptedData = Buffer.concat([
      dataCipher.update(plaintext, 'utf8'),
      dataCipher.final(),
    ]);
    const dataTag = dataCipher.getAuthTag();

    // 3. Encrypt the DEK with the context KEK (same derivation as regular encrypt)
    const kek = this.deriveContextKey(this.activeKey.key, context, tenantId);
    const dekIv = randomBytes(IV_BYTES);
    const dekCipher = createCipheriv('aes-256-gcm', kek, dekIv);
    const encryptedDek = Buffer.concat([dekCipher.update(dek), dekCipher.final()]);
    const dekTag = dekCipher.getAuthTag();

    // 4. Serialize: marker + encDek.dekIv.dekTag.encData.dataIv.dataTag.kid
    const serialized =
      LARGE_FIELD_MARKER +
      [
        encryptedDek.toString('base64'),
        dekIv.toString('base64'),
        dekTag.toString('base64'),
        encryptedData.toString('base64'),
        dataIv.toString('base64'),
        dataTag.toString('base64'),
        this.activeKey.kid,
      ].join(SEPARATOR);

    return toEncryptedValue(serialized);
  }

  async decryptLarge(
    encryptedValue: EncryptedValue,
    context: EncryptionContext,
    tenantId: TenantId,
  ): Promise<string> {
    const raw = (encryptedValue as string).slice(LARGE_FIELD_MARKER.length);
    const parts = raw.split(SEPARATOR);

    if (parts.length !== 7) {
      throw new Error('DECRYPTION_FAILED: invalid large-field encrypted value format');
    }

    const [encDekB64, dekIvB64, dekTagB64, encDataB64, dataIvB64, dataTagB64, kid] =
      parts as [string, string, string, string, string, string, string];

    const masterKey = this.keyring.get(kid);
    if (!masterKey) {
      throw new Error(`DECRYPTION_FAILED: unknown key id '${kid}'`);
    }

    try {
      // 1. Decrypt the DEK using the KEK
      const kek = this.deriveContextKey(masterKey, context, tenantId);
      const dekDecipher = createDecipheriv(
        'aes-256-gcm',
        kek,
        Buffer.from(dekIvB64, 'base64'),
      );
      dekDecipher.setAuthTag(Buffer.from(dekTagB64, 'base64'));
      const dek = Buffer.concat([
        dekDecipher.update(Buffer.from(encDekB64, 'base64')),
        dekDecipher.final(),
      ]);

      // 2. Decrypt the data using the DEK
      const dataDecipher = createDecipheriv(
        'aes-256-gcm',
        dek,
        Buffer.from(dataIvB64, 'base64'),
      );
      dataDecipher.setAuthTag(Buffer.from(dataTagB64, 'base64'));
      const plaintext = Buffer.concat([
        dataDecipher.update(Buffer.from(encDataB64, 'base64')),
        dataDecipher.final(),
      ]);

      return plaintext.toString('utf8');
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('DECRYPTION_FAILED')) throw err;
      throw new Error('DECRYPTION_FAILED: GCM authentication tag mismatch');
    }
  }

  // ── Startup Validation (Section 7.5) ──────────────────────────────────────

  /**
   * Validates all encryption contexts on startup:
   * 1. Roundtrip test: encrypt → decrypt must return original plaintext.
   * 2. Cross-context isolation: decrypting with a different context must fail.
   *
   * Throws if any check fails — prevents the application from starting with
   * misconfigured or corrupted encryption keys.
   */
  async validateEncryptionKeys(): Promise<void> {
    const testPlaintext = 'UICP_ENCRYPTION_ROUNDTRIP_TEST_' + Date.now();
    const testTenantId = TenantId.from('00000000-0000-4000-8000-000000000001');
    const contexts = this.getAllContexts();

    for (const context of contexts) {
      // 1. Roundtrip test
      const encrypted = await this.encrypt(testPlaintext, context, testTenantId);
      const decrypted = await this.decrypt(encrypted, context, testTenantId);

      if (decrypted !== testPlaintext) {
        throw new Error(`Encryption roundtrip failed for context: ${context}`);
      }

      // 2. Cross-context isolation: pick a different context and attempt decrypt
      const otherContext = contexts.find((c) => c !== context);
      if (otherContext) {
        try {
          await this.decrypt(encrypted, otherContext, testTenantId);
          // If we reach here, cross-context isolation is violated
          throw new Error(
            `Cross-context isolation violated: value encrypted with '${context}' was decryptable with '${otherContext}'`,
          );
        } catch (err) {
          if (
            err instanceof Error &&
            err.message.startsWith('Cross-context isolation violated')
          ) {
            throw err;
          }
          // Expected: GCM auth tag mismatch — isolation is working correctly
        }
      }
    }

    this.logger.log(
      `Encryption key validation passed for ${contexts.length} contexts`,
    );
  }

  // ── Private Helpers ────────────────────────────────────────────────────────

  private loadKeys(): void {
    const activeKeyHex = this.config.getOrThrow<string>('ENCRYPTION_MASTER_KEY');
    const activeKid = this.config.getOrThrow<string>('ENCRYPTION_MASTER_KEY_ID');

    const activeKeyBuf = Buffer.from(activeKeyHex, 'hex');
    if (activeKeyBuf.length !== KEY_BYTES) {
      throw new Error(
        `ENCRYPTION_MASTER_KEY must be a 64-char hex string (32 bytes); got ${activeKeyBuf.length} bytes`,
      );
    }

    this.activeKey = { kid: activeKid, key: activeKeyBuf };
    this.keyring.set(activeKid, activeKeyBuf);

    // Load optional deprecated key for rotation support (Req 13.4)
    const deprecatedKeyHex = this.config.get<string>('ENCRYPTION_DEPRECATED_KEY');
    const deprecatedKid = this.config.get<string>('ENCRYPTION_DEPRECATED_KEY_ID');

    if (deprecatedKeyHex && deprecatedKid) {
      const deprecatedKeyBuf = Buffer.from(deprecatedKeyHex, 'hex');
      if (deprecatedKeyBuf.length !== KEY_BYTES) {
        throw new Error(
          `ENCRYPTION_DEPRECATED_KEY must be a 64-char hex string (32 bytes); got ${deprecatedKeyBuf.length} bytes`,
        );
      }
      this.keyring.set(deprecatedKid, deprecatedKeyBuf);
      this.logger.log(`Loaded deprecated encryption key kid=${deprecatedKid}`);
    }

    this.logger.log(`Encryption keys loaded: active kid=${activeKid}, keyring size=${this.keyring.size}`);
  }

  /**
   * Derives a 256-bit context key using HKDF-SHA256.
   *
   * info = context || ':' || tenantId ensures:
   * - Different contexts produce different keys (cross-context isolation).
   * - Different tenants produce different keys (cross-tenant isolation).
   *
   * salt = tenantId bytes — adds entropy from the tenant dimension.
   */
  private deriveContextKey(
    masterKey: Buffer,
    context: EncryptionContext,
    tenantId: TenantId,
  ): Buffer {
    const info = Buffer.from(`${context}:${tenantId.toString()}`, 'utf8');
    const salt = Buffer.from(tenantId.toString(), 'utf8');
    return Buffer.from(hkdfSync('sha256', masterKey, salt, info, KEY_BYTES));
  }

  /**
   * Derives a 256-bit HMAC key using HKDF-SHA256.
   * No tenantId — HMAC keys are context-scoped only so that the same email
   * produces the same hash across tenants (needed for global dedup checks).
   */
  private deriveHmacKey(masterKey: Buffer, context: EncryptionContext): Buffer {
    const info = Buffer.from(`HMAC:${context}`, 'utf8');
    const salt = Buffer.alloc(0); // empty salt — deterministic derivation
    return Buffer.from(hkdfSync('sha256', masterKey, salt, info, KEY_BYTES));
  }

  private getAllContexts(): EncryptionContext[] {
    return [
      'IDENTITY_VALUE',
      'USER_PII',
      'AUDIT_METADATA',
      'TENANT_SETTINGS',
      'OAUTH_PROVIDER_DATA',
      'JWT_PRIVATE_KEY',
    ];
  }
}

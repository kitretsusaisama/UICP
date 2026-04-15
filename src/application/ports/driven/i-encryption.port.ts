import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { EncryptedValue } from '../../../domain/entities/identity.entity';

/**
 * Named encryption contexts — each context derives a distinct key via HKDF.
 * Cross-context decryption always fails (GCM auth tag mismatch).
 */
export type EncryptionContext =
  | 'IDENTITY_VALUE'
  | 'USER_PII'
  | 'AUDIT_METADATA'
  | 'TENANT_SETTINGS'
  | 'OAUTH_PROVIDER_DATA'
  | 'JWT_PRIVATE_KEY';

/**
 * Driven port — AES-256-GCM field-level encryption (Req 13).
 *
 * Contract:
 * - `encrypt` derives a context key via `HKDF(masterKey, tenantId || context)`,
 *   generates a 12-byte random IV, and serializes as
 *   `base64(iv).base64(tag).base64(ciphertext).kid` (Req 13.1–13.3).
 * - `decrypt` selects the master key by `kid` to support deprecated keys (Req 13.4).
 * - `hmac` is deterministic for the same input — used for searchable lookups (Req 13.8).
 * - `encryptLarge` / `decryptLarge` use envelope encryption for fields > 4KB (Req 13.5).
 */
export interface IEncryptionPort {
  /**
   * Encrypt a plaintext value with a tenant-scoped, context-derived key.
   * Returns an opaque `EncryptedValue` in `iv.tag.ciphertext.kid` format.
   */
  encrypt(plaintext: string, context: EncryptionContext, tenantId: TenantId): Promise<EncryptedValue>;

  /**
   * Decrypt an `EncryptedValue` produced by `encrypt`.
   * Throws if the GCM auth tag fails (wrong context, wrong tenant, or tampered data).
   */
  decrypt(encryptedValue: EncryptedValue, context: EncryptionContext, tenantId: TenantId): Promise<string>;

  /**
   * Compute a deterministic HMAC-SHA256 of a value using a context-derived key.
   * Used to create searchable lookup hashes for encrypted identity fields.
   */
  hmac(value: string, context: EncryptionContext): Promise<string>;

  /**
   * Envelope-encrypt a large value (> 4KB).
   * Generates a per-field DEK encrypted with the context KEK.
   */
  encryptLarge(plaintext: string, context: EncryptionContext, tenantId: TenantId): Promise<EncryptedValue>;

  /**
   * Decrypt a value produced by `encryptLarge`.
   */
  decryptLarge(encryptedValue: EncryptedValue, context: EncryptionContext, tenantId: TenantId): Promise<string>;
}

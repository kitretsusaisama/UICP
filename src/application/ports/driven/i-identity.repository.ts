import { Identity, IdentityType } from '../../../domain/entities/identity.entity';
import { IdentityId } from '../../../domain/value-objects/identity-id.vo';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

/**
 * Driven port — identity persistence (Section 4.2).
 *
 * Contract:
 * - All methods MUST include `tenant_id` in WHERE clauses (Req 1.1, 1.2).
 * - `findByHash` is O(1) via UNIQUE KEY on (tenant_id, type, value_hash).
 * - `save` throws `ConflictException(IDENTITY_ALREADY_EXISTS)` on duplicate key.
 * - `verify` uses optimistic locking (version check).
 * - All methods throw `InfrastructureException(DB_UNAVAILABLE)` on connection failure.
 */
export interface IIdentityRepository {
  /**
   * Find an identity by its HMAC hash — no decryption needed for equality checks.
   * Routes to read replica.
   */
  findByHash(valueHash: string, type: IdentityType, tenantId: TenantId): Promise<Identity | null>;

  /**
   * Find all identities linked to a user.
   * Routes to read replica.
   */
  findByUserId(userId: UserId, tenantId: TenantId): Promise<Identity[]>;

  /**
   * Find an OAuth identity by provider subject ID (dedup check).
   * Routes to read replica.
   */
  findByProviderSub(providerSub: string, type: IdentityType, tenantId: TenantId): Promise<Identity | null>;

  /**
   * Persist a new identity (INSERT).
   * MUST be called within an existing DB transaction.
   * Throws `ConflictException(IDENTITY_ALREADY_EXISTS)` on duplicate key.
   */
  save(identity: Identity): Promise<void>;

  /**
   * Mark an identity as verified.
   * Uses optimistic locking (version check).
   */
  verify(identityId: IdentityId, tenantId: TenantId): Promise<void>;
}

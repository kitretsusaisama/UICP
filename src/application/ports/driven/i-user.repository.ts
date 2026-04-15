import { User } from '../../../domain/aggregates/user.aggregate';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

/**
 * Driven port — user persistence.
 *
 * Contract:
 * - Every method MUST include `tenant_id` in all generated SQL (Req 1.1, 1.2).
 * - `findById` / `findByTenantId` route to read replica.
 * - `save` / `update` route to primary.
 * - `update` uses optimistic locking via the `version` column; throws
 *   `ConflictException(VERSION_CONFLICT)` on mismatch (Req 2.7).
 */
export interface IUserRepository {
  /**
   * Load a single user by ID within a tenant.
   * Returns null when not found.
   */
  findById(userId: UserId, tenantId: TenantId): Promise<User | null>;

  /**
   * List all users belonging to a tenant (paginated by the caller).
   */
  findByTenantId(tenantId: TenantId): Promise<User[]>;

  /**
   * Persist a newly created user aggregate (INSERT).
   * Throws `ConflictException(IDENTITY_ALREADY_EXISTS)` on duplicate key.
   */
  save(user: User): Promise<void>;

  /**
   * Persist mutations to an existing user aggregate (UPDATE).
   * Uses optimistic locking — throws `ConflictException(VERSION_CONFLICT)`
   * when the stored version differs from `user.getVersion()`.
   */
  update(user: User): Promise<void>;
}

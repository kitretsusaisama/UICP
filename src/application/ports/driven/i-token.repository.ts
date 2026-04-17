import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

/** Persisted refresh token record. */
export interface RefreshTokenRecord {
  jti: string;
  familyId: string;
  userId: string;
  tenantId: string;
  /** Whether this token has been rotated (consumed). */
  revoked: boolean;
  expiresAt: Date;
  createdAt: Date;
}

/**
 * Driven port — JWT token lifecycle management.
 *
 * Contract:
 * - `addToBlocklist` stores `jti` in a Redis sorted set with expiry as score,
 *   enabling O(1) blocklist checks via ZSCORE (Req 7.5).
 * - `isBlocklisted` is O(1) — no DB round trips for access token validation (Req 7.7).
 * - `revokeFamily` revokes all tokens sharing the same `familyId` (Req 7.4).
 */
export interface ITokenRepository {
  /**
   * Persist a new refresh token record (INSERT).
   */
  saveRefreshToken(record: RefreshTokenRecord): Promise<void>;

  /**
   * Load a refresh token by its JTI.
   * Returns null when not found or already expired.
   */
  findRefreshToken(jti: string, tenantId: TenantId): Promise<RefreshTokenRecord | null>;

  /**
   * Mark a single refresh token as revoked.
   */
  revokeToken(jti: string, tenantId: TenantId): Promise<void>;

  /**
   * Atomically rotate a refresh token: revoke the old one and save the new one in a single transaction.
   * Prevents edge cases where a crash between revoking and saving leaves the user permanently logged out.
   */
  rotateRefreshToken(oldJti: string, tenantId: TenantId, newRecord: RefreshTokenRecord): Promise<void>;

  /**
   * Revoke all refresh tokens in a token family (reuse-detection response).
   */
  revokeFamily(familyId: string, tenantId: TenantId): Promise<void>;

  /**
   * Revoke all token families for a user (logout-all / password change).
   */
  revokeAllFamiliesByUser(userId: UserId, tenantId: TenantId): Promise<void>;

  /**
   * Check whether a JWT JTI is in the Redis blocklist.
   * O(1) via Redis ZSCORE.
   */
  isBlocklisted(jti: string): Promise<boolean>;

  /**
   * Add a JWT JTI to the Redis blocklist with the token's remaining TTL as score.
   * Automatically expires when the token would have expired anyway.
   */
  addToBlocklist(jti: string, expiresAt: Date): Promise<void>;

  /**
   * Return all active (non-revoked, non-expired) JTIs for a user.
   * Used by logout-all to bulk-blocklist access tokens.
   */
  getActiveJtisByUser(userId: UserId, tenantId: TenantId): Promise<string[]>;
}

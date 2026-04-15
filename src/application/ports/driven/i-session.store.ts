import { Session, SessionStatus } from '../../../domain/aggregates/session.aggregate';
import { SessionId } from '../../../domain/value-objects/session-id.vo';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

/**
 * Driven port — session storage (Redis-backed).
 *
 * Contract:
 * - Sessions are stored as Redis Hashes with TTL = tenant's `session_ttl_s` (Req 8.1).
 * - `create` adds the session ID to a Redis Sorted Set keyed by
 *   `user-sessions:{tenantId}:{userId}` with creation timestamp as score (Req 8.2).
 * - When `max_sessions_per_user` is reached, the oldest session is evicted (Req 8.3).
 * - `extendTtl` implements sliding TTL (Req 8.4).
 */
export interface ISessionStore {
  /**
   * Persist a new session and register it in the user's session sorted set.
   * Evicts the oldest session when the per-user limit is reached.
   */
  create(session: Session, ttlSeconds: number): Promise<void>;

  /**
   * Load a session by ID.
   * Returns null when not found or TTL has elapsed.
   */
  findById(sessionId: SessionId, tenantId: TenantId): Promise<Session | null>;

  /**
   * List all active session IDs for a user (from the sorted set).
   */
  findByUserId(userId: UserId, tenantId: TenantId): Promise<Session[]>;

  /**
   * Remove a session from Redis and from the user's sorted set.
   */
  invalidate(sessionId: SessionId, tenantId: TenantId): Promise<void>;

  /**
   * Remove all sessions for a user (logout-all flow).
   */
  invalidateAll(userId: UserId, tenantId: TenantId): Promise<void>;

  /**
   * Reset the session TTL to the full `ttlSeconds` value (sliding TTL).
   * No-op if the session no longer exists.
   */
  extendTtl(sessionId: SessionId, tenantId: TenantId, ttlSeconds: number): Promise<void>;

  /**
   * Update the session status field in the Redis Hash.
   * Used to transition MFA_PENDING → ACTIVE after OTP verification.
   */
  setStatus(sessionId: SessionId, tenantId: TenantId, status: SessionStatus): Promise<void>;
}

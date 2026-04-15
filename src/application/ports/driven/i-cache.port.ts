/**
 * Driven port — generic Redis cache operations.
 *
 * Contract:
 * - All commands are wrapped with a circuit breaker (Req 15.1).
 * - Supports Redis Cluster with `{userId}` hash tags for session key co-location.
 * - Throws `InfrastructureException(CACHE_UNAVAILABLE)` when the circuit is open
 *   and no fallback is configured.
 */
export interface ICachePort {
  /**
   * Get a value by key.
   * Returns null when the key does not exist or has expired.
   */
  get(key: string): Promise<string | null>;

  /**
   * Set a key-value pair with an optional TTL in seconds.
   */
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;

  /**
   * Delete a key.
   */
  del(key: string): Promise<void>;

  /**
   * Atomically get and delete a key.
   * Returns null when the key does not exist.
   */
  getdel(key: string): Promise<string | null>;

  /**
   * Check whether a value is a member of a Redis Set.
   * Returns true when the member exists.
   */
  sismember(key: string, member: string): Promise<boolean>;

  /**
   * Add one or more members to a Redis Set.
   */
  sadd(key: string, ...members: string[]): Promise<number>;

  /**
   * Remove one or more members from a Redis Set.
   */
  srem(key: string, ...members: string[]): Promise<number>;

  /**
   * Return all members of a Redis Set.
   */
  smembers(key: string): Promise<string[]>;

  /**
   * Atomically increment an integer counter.
   * Creates the key with value 1 if it does not exist.
   */
  incr(key: string): Promise<number>;

  /**
   * Set the TTL (in seconds) on an existing key.
   * Returns true when the TTL was set, false when the key does not exist.
   */
  expire(key: string, ttlSeconds: number): Promise<boolean>;
}

import { Injectable, Logger } from '@nestjs/common';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { AuthSession } from '../../domain/auth-session/auth-session.entity';
import { RedisCacheAdapter } from '../cache/redis-cache.adapter';

/**
 * Auth Session Repository - Redis-backed storage
 *
 * Key layout:
 *   auth-session:{tenantId}:{sessionId} → Redis Hash
 */
@Injectable()
export class AuthSessionRepository {
  private readonly logger = new Logger(AuthSessionRepository.name);
  private readonly DEFAULT_TTL = 3600; // 1 hour

  constructor(private readonly cache: RedisCacheAdapter) {}

  private key(tenantId: TenantId, sessionId: string): string {
    return `auth-session:${tenantId.toString()}:${sessionId}`;
  }

  async save(session: AuthSession, ttlSeconds: number = this.DEFAULT_TTL): Promise<void> {
    const key = this.key(session.tenantId, session.id);
    const fields = session.toRedisHash();

    const client = this.cache.getClient();
    await client.hset(key, fields);
    await client.expire(key, ttlSeconds);

    this.logger.debug({ sessionId: session.id, tenantId: session.tenantId.toString() }, 'Auth session saved');
  }

  async findById(tenantId: TenantId, sessionId: string): Promise<AuthSession | null> {
    const key = this.key(tenantId, sessionId);
    const client = this.cache.getClient();

    const exists = await client.exists(key);
    if (!exists) {
      return null;
    }

    const fields = await client.hgetall(key);
    if (!fields || Object.keys(fields).length === 0) {
      return null;
    }

    return AuthSession.fromRedisHash(fields as Record<string, string>);
  }

  async delete(tenantId: TenantId, sessionId: string): Promise<void> {
    const key = this.key(tenantId, sessionId);
    const client = this.cache.getClient();
    await client.del(key);

    this.logger.debug({ sessionId, tenantId: tenantId.toString() }, 'Auth session deleted');
  }

  async extendTtl(tenantId: TenantId, sessionId: string, ttlSeconds: number): Promise<void> {
    const key = this.key(tenantId, sessionId);
    const client = this.cache.getClient();
    await client.expire(key, ttlSeconds);
  }

  async exists(tenantId: TenantId, sessionId: string): Promise<boolean> {
    const key = this.key(tenantId, sessionId);
    const client = this.cache.getClient();
    const result = await client.exists(key);
    return result === 1;
  }
}
import { Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis, { Cluster } from 'ioredis';
import { ICachePort } from '../../application/ports/driven/i-cache.port';
import { CircuitBreaker, CIRCUIT_BREAKER_CONFIGS } from '../resilience/circuit-breaker';
import { IMetricsPort } from '../../application/ports/driven/i-metrics.port';
import { ITracerPort } from '../../application/ports/driven/i-tracer.port';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';

type RedisClient = Redis | Cluster;

/**
 * Redis cache adapter implementing ICachePort.
 *
 * - Supports both standalone Redis and Redis Cluster (auto-detected via REDIS_CLUSTER env var).
 * - All commands are wrapped with a circuit breaker (Req 15.1).
 * - Redis Cluster keys use `{userId}` hash tags for session key co-location (Req 8.2).
 * - When the circuit is OPEN, throws an error with code CACHE_UNAVAILABLE.
 */
@Injectable()
export class RedisCacheAdapter implements ICachePort, OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisCacheAdapter.name);
  private client!: RedisClient;

  // ── Circuit Breaker ────────────────────────────────────────────────────────
  private readonly circuitBreaker: CircuitBreaker<unknown>;

  constructor(
    private readonly config: ConfigService,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
    @Optional() @Inject(INJECTION_TOKENS.TRACER_PORT) private readonly tracer?: ITracerPort,
  ) {
    this.circuitBreaker = new CircuitBreaker(CIRCUIT_BREAKER_CONFIGS.redis, metrics);
  }

  onModuleInit(): void {
    const isCluster = this.config.get<string>('REDIS_CLUSTER') === 'true';
    const host = this.config.get<string>('REDIS_HOST') ?? 'localhost';
    const port = this.config.get<number>('REDIS_PORT') ?? 6379;
    const password = this.config.get<string>('REDIS_PASSWORD');
    const tls = this.config.get<string>('REDIS_TLS') === 'true';

    const redisOptions = {
      password,
      tls: tls ? {} : undefined,
      lazyConnect: true,
      enableReadyCheck: true,
      maxRetriesPerRequest: 1,
    };

    if (isCluster) {
      const nodes = this.config
        .get<string>('REDIS_CLUSTER_NODES', `${host}:${port}`)
        .split(',')
        .map((n) => {
          const [h, p] = n.trim().split(':');
          return { host: h, port: parseInt(p ?? '6379', 10) };
        });

      this.client = new Cluster(nodes, {
        redisOptions,
        clusterRetryStrategy: (times) => Math.min(times * 100, 3000),
      });
    } else {
      this.client = new Redis({ host, port, ...redisOptions });
    }

    this.client.on('error', (err: Error) => {
      this.logger.error({ err }, 'Redis connection error');
    });

    this.client.on('connect', () => {
      this.logger.log('Redis connected');
    });
  }

  async onModuleDestroy(): Promise<void> {
    await this.client.quit();
  }

  // ── ICachePort ─────────────────────────────────────────────────────────────

  async get(key: string): Promise<string | null> {
    return this.execute(() => this.client.get(key));
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    await this.execute(async () => {
      if (ttlSeconds !== undefined && ttlSeconds > 0) {
        await this.client.set(key, value, 'EX', ttlSeconds);
      } else {
        await this.client.set(key, value);
      }
    });
  }

  async del(key: string): Promise<void> {
    await this.execute(() => this.client.del(key));
  }

  async getdel(key: string): Promise<string | null> {
    return this.execute(() => (this.client as Redis).getdel(key));
  }

  async sismember(key: string, member: string): Promise<boolean> {
    const result = await this.execute(() => this.client.sismember(key, member));
    return result === 1;
  }

  async sadd(key: string, ...members: string[]): Promise<number> {
    return this.execute(() => this.client.sadd(key, ...members));
  }

  async srem(key: string, ...members: string[]): Promise<number> {
    return this.execute(() => this.client.srem(key, ...members));
  }

  async smembers(key: string): Promise<string[]> {
    return this.execute(() => this.client.smembers(key));
  }

  async incr(key: string): Promise<number> {
    return this.execute(() => this.client.incr(key));
  }

  async expire(key: string, ttlSeconds: number): Promise<boolean> {
    const result = await this.execute(() => this.client.expire(key, ttlSeconds));
    return result === 1;
  }

  // ── Circuit Breaker ────────────────────────────────────────────────────────

  private async execute<T>(fn: () => Promise<T>): Promise<T> {
    try {
      const result = await (this.circuitBreaker as CircuitBreaker<T>).execute(fn);
      this.tracer?.setAttributes({ 'db.system': 'redis', 'cache.hit': result !== null });
      return result;
    } catch (err: any) {
      if (err?.code === 'CIRCUIT_OPEN') {
        throw Object.assign(
          new Error('CACHE_UNAVAILABLE: Redis circuit breaker is OPEN'),
          { code: 'CACHE_UNAVAILABLE' },
        );
      }
      throw err;
    }
  }

  /**
   * Returns true when the Redis circuit breaker is OPEN.
   * Used by fallback-aware adapters (e.g., session store, lock adapter).
   */
  isCircuitOpen(): boolean {
    return this.circuitBreaker.isOpen();
  }

  /** Expose the underlying client for adapters that need raw access (e.g. session store). */
  getClient(): RedisClient {
    return this.client;
  }
}

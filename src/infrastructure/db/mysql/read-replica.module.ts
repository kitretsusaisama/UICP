import { DynamicModule, Module, Provider } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MYSQL_POOL, DbPool } from './mysql.module';

/** Injection token for the read replica pool */
export const MYSQL_READ_REPLICA_POOL = Symbol('MYSQL_READ_REPLICA_POOL');

/** Injection token for the database router */
export const DB_ROUTER = Symbol('DB_ROUTER');

export interface ReadReplicaPool extends DbPool {
  isReplica: true;
}

export interface DatabaseRouter {
  /** Get primary pool for write operations */
  getPrimary(): DbPool;
  /** Get replica pool for read operations */
  getReplica(): DbPool | null;
  /** Get appropriate pool based on operation type */
  getPool(forWrite: boolean): DbPool;
}

/**
 * ReadReplicaModule — provides read replica routing for query optimization.
 *
 * Configure in .env (supports both naming conventions):
 * - DB_REPLICA_HOST or MYSQL_REPLICA_HOST - replica host (optional)
 * - DB_REPLICA_PORT or MYSQL_REPLICA_PORT - replica port (default: 3306)
 * - DB_REPLICA_USER or MYSQL_REPLICA_USER - replica user
 * - DB_REPLICA_PASSWORD or MYSQL_REPLICA_PASSWORD - replica password
 * - DB_REPLICA_NAME or MYSQL_REPLICA_DB - replica database name
 * - DB_REPLICA_POOL_MAX - max connections (default: 10)
 *
 * Usage:
 * - Inject DB_ROUTER and call getReplica() for read operations
 * - Repositories can check isReplica to optimize queries
 */
@Module({})
export class ReadReplicaModule {
  static forRoot(): DynamicModule {
    const replicaPoolProvider: Provider = {
      provide: MYSQL_READ_REPLICA_POOL,
      useFactory: (config: ConfigService): ReadReplicaPool | null => {
        // Check both naming conventions
        const replicaHost = config.get<string>('DB_REPLICA_HOST') || config.get<string>('MYSQL_REPLICA_HOST');

        // If no replica configured, return null (read replica disabled)
        if (!replicaHost) {
          return null;
        }

        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const mysql = require('mysql2/promise') as { createPool: (opts: Record<string, unknown>) => DbPool };

        const pool = mysql.createPool({
          host: replicaHost,
          port: config.get<number>('DB_REPLICA_PORT') ?? config.get<number>('MYSQL_REPLICA_PORT') ?? 3306,
          user: config.get<string>('DB_REPLICA_USER') ?? config.get<string>('MYSQL_REPLICA_USER'),
          password: config.get<string>('DB_REPLICA_PASSWORD') ?? config.get<string>('MYSQL_REPLICA_PASSWORD'),
          database: config.get<string>('DB_REPLICA_NAME') ?? config.get<string>('MYSQL_REPLICA_DB') ?? config.get<string>('DB_NAME'),
          connectionLimit: config.get<number>('DB_REPLICA_POOL_MAX') ?? 10,
          waitForConnections: true,
          queueLimit: 20,
          idleTimeout: 30_000,
          connectTimeout: 5_000,
          enableKeepAlive: true,
          keepAliveInitialDelay: 10_000,
          timezone: '+00:00',
          dateStrings: false,
          supportBigNumbers: true,
          bigNumberStrings: false,
        }) as ReadReplicaPool;

        pool.isReplica = true;
        return pool;
      },
      inject: [ConfigService],
    };

    const routerProvider: Provider = {
      provide: DB_ROUTER,
      useFactory: (primaryPool: DbPool, replicaPool: ReadReplicaPool | null): DatabaseRouter => {
        return {
          getPrimary: () => primaryPool,
          getReplica: () => replicaPool,
          getPool: (forWrite: boolean): DbPool => {
            if (forWrite) {
              return primaryPool;
            }
            // For reads: prefer replica if available, fall back to primary
            return replicaPool ?? primaryPool;
          },
        };
      },
      inject: [MYSQL_POOL, MYSQL_READ_REPLICA_POOL],
    };

    return {
      module: ReadReplicaModule,
      providers: [replicaPoolProvider, routerProvider],
      exports: [MYSQL_READ_REPLICA_POOL, DB_ROUTER],
      global: true,
    };
  }
}